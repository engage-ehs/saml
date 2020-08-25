package saml

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/beevik/etree"
)

type Subject string

// Check validates the SAML response received from the remote part. Additional checkers can be given
// to provide a stricter acceptance.
//
// https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-CoreValidation
func Check(from io.Reader, checkers ...Checker) (Principal, error) {
	doc := etree.NewDocument()
	// read the full info
	if _, err := doc.ReadFrom(from); err != nil {
		return UnAuth, err
	}
	rsp := doc.Root()
	if rsp == nil || rsp.Tag != "Response" {
		return UnAuth, errors.New("no SAML response")
	}

	// get canonical info
	if rsp.SelectAttrValue("Version", "") != "2.0" {
		return UnAuth, errors.New("SAML version not supported")
	}
	if rsp.SelectAttr("ID") == nil {
		return UnAuth, errors.New("missing ID attribute in SAML response")
	}
	pcp := ppInResponse(rsp)
	if err := checkStatus(rsp); err != nil {
		return pcp, err
	}

	if len(rsp.FindElements("//Assertion")) != 1 {
		return pcp, errors.New("SAML response must contain only 1 assertion")
	}

	elts, err := findSignedElements(rsp)
	if err != nil {
		return pcp, err
	}

	if len(elts) == 0 {
		return pcp, nil
	}

	// we take the first element, because the response always contains the assertion, so either
	// works
	e := elts[0]
	sig := e.SelectElement("Signature")
	if sig == nil {
		return pcp, errors.New("no signature")
	}

	sv, err := extractSignature(sig)
	if err != nil {
		return pcp, fmt.Errorf("invalid signature value: %w", err)
	}

	algo, err := findSignatureMethod(sig)
	if err != nil {
		return pcp, fmt.Errorf("invalid signature method: %w", err)
	}
	cert, err := findCertificate(sig)
	if err != nil {
		return pcp, fmt.Errorf("invalid certificate: %w", err)
	}

	var algocheck bytes.Buffer
	si := sig.SelectElement("SignedInfo")
	canonicalize(si, &algocheck, &pt{})

	if err := cert.CheckSignature(algo, algocheck.Bytes(), sv); err != nil {
		return pcp, err
	}

	dv, err := findDigestValue(sig)
	if err != nil {
		return pcp, fmt.Errorf("invalid digest value")
	}

	digest, err := findDigestAlgo(sig)
	if err != nil {
		return pcp, fmt.Errorf("invalid digest method: %w", err)
	}

	sig.Parent().RemoveChild(sig)
	canonicalize(e, digest, &pt{})

	if !equal(digest.Sum(nil), dv) {
		return pcp, errors.New("digest does not match expected value")
	}
	// don’t return the cert if it did not sign the right value (prevent misuse, where the
	// issuer on the cert would be used for further work, and opening the door to timing
	// attacks).
	pcp.Cert = cert

	if isResponse(e) {
		e = e.FindElement(".//Assertion")
	}
	if err := ppInAssertion(e, &pcp); err != nil {
		return pcp, err
	}

	for _, c := range checkers {
		if err := c(pcp); err != nil {
			return pcp, err
		}
	}

	return pcp, nil
}

func checkStatus(rsp *etree.Element) error {
	code := rsp.FindElement("//StatusCode")
	if code == nil {
		return errors.New("no status code")
	}

	if got := code.SelectAttrValue("Value", ""); got != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return errors.New("invalid code value " + got)
	}

	return nil
}

// implementation note: the returned elements must be assertions or response, signed by a signature
// element as a top-level child.
func findSignedElements(rsp *etree.Element) (elts []*etree.Element, _ error) {
	for _, sig := range rsp.FindElements("//Signature") {
		ref := sig.FindElement("./SignedInfo/Reference")
		if ref == nil {
			return nil, errors.New("missing reference")
		}

		id := ref.SelectAttrValue("URI", "")
		if len(id) == 0 || id[0] != '#' {
			return nil, errors.New("invalid reference URI " + id)
		}
		id = id[1:] // drop local prefix
		sel, err := etree.CompilePath(fmt.Sprintf("[@ID='%s']", id))
		if err != nil {
			return nil, fmt.Errorf("invalid path [@ID='%s']: %w", id, err)
		}

		elt := rsp.FindElementPath(sel)
		if elt == nil {
			return nil, errors.New("no element matching ID " + id)
		}

		if !isResponse(elt) && !isAssertion(elt) {
			return nil, fmt.Errorf("element ID %s is not an assertion or response", id)
		}

		elts = append(elts, elt)
	}

	return
}

func isResponse(elt *etree.Element) bool  { return elt.Tag == "Response" }
func isAssertion(elt *etree.Element) bool { return elt.Tag == "Assertion" }

func extractSignature(sig *etree.Element) ([]byte, error) {
	sv := sig.SelectElement("SignatureValue")
	if sv == nil {
		return nil, errors.New("no signature value")
	}
	sv.Parent().RemoveChild(sv)

	return base64.StdEncoding.DecodeString(sv.Child[0].(*etree.CharData).Data)
}

func findSignatureMethod(sig *etree.Element) (x509.SignatureAlgorithm, error) {
	sm := sig.FindElement(".//SignatureMethod")
	if sm == nil {
		return x509.UnknownSignatureAlgorithm, errors.New("no signature method")
	}
	algos := sm.SelectAttrValue("Algorithm", "")
	var algo x509.SignatureAlgorithm
	switch algos {
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		algo = x509.SHA256WithRSA
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		algo = x509.SHA1WithRSA
	default:
		return x509.UnknownSignatureAlgorithm, errors.New("unknown algoritm " + algos)
	}

	return algo, nil
}

func findDigestAlgo(sig *etree.Element) (hash.Hash, error) {
	dm := sig.FindElement(".//DigestMethod")
	if dm == nil {
		return nil, errors.New("no digest method")
	}

	switch dm.SelectAttrValue("Algorithm", "") {
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return sha256.New(), nil
	case "http://www.w3.org/2000/09/xmldsig#sha1":
		return sha1.New(), nil
	default:
		return nil, errors.New("unknown digest method " + dm.SelectAttrValue("Algorithm", ""))
	}
}

func findCertificate(sig *etree.Element) (*x509.Certificate, error) {
	ce := sig.FindElement(".//X509Certificate")
	if ce == nil || len(ce.Child) != 1 {
		return nil, errors.New("no certificate")
	}
	cb, err := base64.StdEncoding.DecodeString(ce.Text())
	if err != nil {
		return nil, errors.New("invalid certificate")
	}

	return x509.ParseCertificate(cb)
}

func findDigestValue(sig *etree.Element) ([]byte, error) {
	dv := sig.FindElement(".//DigestValue")
	if dv == nil || len(dv.Child) != 1 {
		return nil, errors.New("invalid digest value")
	}

	return base64.StdEncoding.DecodeString(dv.Text())
}

func equal(mac1, mac2 []byte) bool {
	// We don't have to be constant time if the lengths of the MACs are different as that
	// suggests that a completely different hash function was used.
	return subtle.ConstantTimeCompare(mac1, mac2) == 1
}
