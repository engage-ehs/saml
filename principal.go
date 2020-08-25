package saml

import (
	"crypto/x509"
	"errors"

	"github.com/beevik/etree"
)

// Principal is the person identified by SAML. Only signed information is returned.
type Principal struct {
	// Elements in response or assertion (spec § 2.3.3), if in the response, the response must
	// be signed. Clients can rely on this being signed by the certificate.
	Attributes map[string]string
	Conditions map[string]string

	Subject string
	Issuer  string

	Cert *x509.Certificate

	// Element in response (spec § 3.2.2), might not be signed
	InResponseTo string
	Destination  string
}

var UnAuth Principal

// read principal info from response
func ppInResponse(elt *etree.Element) Principal {
	p := Principal{Attributes: make(map[string]string), Conditions: make(map[string]string)}

	if dst := elt.SelectAttrValue("Destination", ""); dst != "" {
		p.Destination = dst
	}

	if rto := elt.SelectAttrValue("InResponseTo", ""); rto != "" {
		p.InResponseTo = rto
	}

	return p
}

// read principal info from assertion. can only be called after we checked the crypto.
func ppInAssertion(elt *etree.Element, pcp *Principal) error {
	ni := elt.FindElement("./Subject/NameID")
	if ni == nil {
		return errors.New("no subject name")
	}
	pcp.Subject = ni.Text()

	attr := elt.FindElements("./AttributeStatement/Attribute")
	for _, at := range attr {
		name := at.SelectAttrValue("Name", "")
		v := at.SelectElement("AttributeValue")
		if v == nil {
			return errors.New("invalid attribute " + name)
		}

		pcp.Attributes[name] = v.Text()
	}

	if issuer := elt.FindElement("./Issuer"); issuer == nil {
		return errors.New("no issuer in assertion")
	} else {
		pcp.Issuer = issuer.Text()
	}

	cond := elt.FindElement(".//Conditions")
	for _, at := range cond.Attr {
		pcp.Conditions[at.Key] = at.Value
	}

	// override response one if in assertion, so we can get it signed if possible
	if rsp := elt.FindElement(".//SubjectConfirmationData"); rsp != nil {
		pcp.InResponseTo = rsp.SelectAttrValue("InResponseTo", "")
	}

	return nil
}
