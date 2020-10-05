package saml

import (
	"crypto/x509"
	"fmt"
	"time"
)

// A Checker is a predicate against a signed element. The element can be a response or an assertion,
// but bear in mind that all not data might be signed. Checkers in this package will mention when
// they operate on the assertion only (in which case they require signed values).
type Checker func(Principal) error

// InResponseTo rejects unsolicited responses
func InResponseTo(id string) Checker {
	return func(p Principal) error {
		if id == p.InResponseTo {
			return nil
		}

		return fmt.Errorf("invalid response to: %s", p.InResponseTo)
	}
}

// ValidTimestamp accepts only assertion still currently valid. Leeway parameter allows to accept
// SAML providers which are known to be too slow, and where a strict validation would result in
// rejecting too many legitimate login attempts.
func ValidTimestamp(leeway time.Duration) Checker {
	return func(p Principal) error {
		nb, err := time.Parse("2006-01-02T15:04:05.999Z", p.Conditions["NotBefore"])
		if err != nil || nb.Add(-leeway).Before(time.Now()) {
			return fmt.Errorf("Assertion only valid after %s", nb)
		}

		na, err := time.Parse("2006-01-02T15:04:05.999Z", p.Conditions["NotOnOrAfter"])
		if err != nil || na.Add(leeway).After(time.Now()) {
			return fmt.Errorf("Assertion only valid before %s", na)
		}

		return nil
	}
}

// AcceptableCertificate checks that the certificate used to sign the assertion is valid for a given
// issuer. The pool is used as a root of trust.
func AcceptableCertificate(jar interface {
	Find(issuer string) *x509.CertPool
}) Checker {
	return func(p Principal) error {
		pool := jar.Find(p.Issuer)
		if pool == nil {
			return fmt.Errorf("unknown issuer")
		}

		cs, err := p.Cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: acceptTime})
		if err != nil {
			return err
		}
		if len(cs) == 0 {
			return fmt.Errorf("no chain of verification could be created")
		}

		return nil
	}
}

type JarFunc func(string) *x509.CertPool

func (jf JarFunc) Find(issuer string) *x509.CertPool { return jf(issuer) }

var acceptTime time.Time // can be set to accept older certificates. Reset to zero after use (in test only)

const StrictTime = 0

// Validate assertion time
// AuthN statement
// check destination
// check audiences
// check issuers
// check session expiration
// validate subject confirmation
// check signed response
// check signed assertion
