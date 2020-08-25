package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"
)

func TestReadSAMLSignature(t *testing.T) {
	ff, err := filepath.Glob("testdata/*samlresponse.txt")
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range ff {
		dt, err := ioutil.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}

		dbuf := make([]byte, base64.StdEncoding.EncodedLen(len(dt)))
		sz, err := base64.StdEncoding.Decode(dbuf, dt)
		if err != nil {
			t.Fatal(err)
		}

		cp := bytes.NewReader(dbuf[:sz])
		p, err := Check(cp,
			AcceptableCertificate(myjar),
		)
		if err != nil {
			t.Fatal(m, err)
		}

		acceptTime = time.Now()
		t.Log(p)
	}

	acceptTime = time.Time{}
}

var certs = map[string][]string{
	"https://sts.windows.net/2de968fb-151a-452c-9db6-ff6f72d21853/":      {`MIIDBTCCAe2gAwIBAgIQIKS1IbCfX7xH/fHDCq11ljANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE5MDQyNDAwMDAwMFoXDTIxMDQyNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI5kVi26Ld1VpO1R4M3VEtDmnPxWOH38/n18qpRRQcmMWHCNl9QZudZAX8O2A7w8UxHsOchhAhJSglGjaHuHlnNDgqyzU4rIyyd6EtF4UdAwypvIgdeXIsgqScR6KoTff3wY6WjgbnCijcyllNHQbvG4l/70t4dIa9gXOjORvWFTyFgazhj38M1K5N3d4IpMjRfJU78Vhc1I/crlIbsJQ9lLgBLcMCk9Cwu2mc/ho7kcFMZ7jTUpT4nt4pq5RniCNbZyCzSe2wt3Sb6E6/TPZabQE4Q5BRWoabLErAoq+HQZFYg0zLA8OQgvY7T1ik8B99z+n0q3MMZdIGSSqRTZRssCAwEAAaMhMB8wHQYDVR0OBBYEFFjkfvrQ97CY5HSyrhd98vkwj0SuMA0GCSqGSIb3DQEBCwUAA4IBAQAHVEnT+HZIxZc2jIdPqKcwCyCR4t44dsDTLYpvLB87iAJHckWgSblqgi/2hgW773PURIFSVWZbyT+/EgDPy0Bd+SHn0P9f4dOSrEWK6Ug3/GsOnUzooJ4SNcP91Shv5y5n5kCcZuglpnTBil85q+ZgB44CXQ5dPzDlZgO2IcCi2ZCYPGZUvKWSFnkQa0pjXu6wAArj1wWGbX7LuaPsSkOD1MK0A1/ve9V9kTeYr0fmmP+hD2TtOY+5fcv9oMbMQuL99Pwr+erjN3dDz7bQ0SDK+E8cerYgorHqjSIxbgH55yR9M1ca8sRriTl8Ah0rLAp/JIpFzn35oyrzCf6zzzWh`, `MIIC8DCCAdigAwIBAgIQJ/xC//wuw6tDR2DrwLDR2DANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0xODEyMDQxMjEzNTBaFw0yMTEyMDQxMjEzNTBaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3MSFE90KfTbcAOb4smVctSSI1WYIcMQdy5BCTmYxWCgCDx9iI8RtqtSeSLYRT63vt0R5RrJVq5Zc+XnTNKmaNFRnaee06QWtXzt3IajX5TRbRVf5tm20sNsuEIn1q5SU7Gs7h5pDo8pjtQhyJA5h/1LH67x8l29MDRJDNN1nGAlexmh5mBNOAq3fTHvwo4sequYerLy+7M7oAgGnrxpUkgSDJpOAYGIH2+sL6JDW//+AUgYC1Y4eIJ6kPY9ge8CloTTtJYL3odeAWi0Nf2Z6NDpQzUDJ59cUfZx3kmksqqVjG+QVm/o4YyD/n6eEtvVQ3EXnk0s1zpZstLMAUApxkQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCQU2kRdXPHGQ/wtVCiFbAtIuL2Vo38I4HoBbQEaqefaxphLZRMIxtQuXqUPujyzbKnS2ntLI2FrK6tTznMeOwsIu/eyqifwhCJGN69XHvWeHDAUaWqmlc8gLYyCjRLJ+AMSmHqi/oeWDo3/Zdj+SJJdAimimZ738vdR7A/nhKhSNCOUSoj1wHFzpqBzWWV4yTplbP6NZwpduu84UicyY5guWq6JbvhhwOMEeONQzJd+y1XcEhX/UbHmROvrrvAgdErKtBNR2T8PkajFWopd/Q1ZZru2WZFGVS2rezpcydTsLw/vvThFzeiv2dF77oIVyd3xhEOgJfp+Ea+F5R8D7A7`},
	"http://www.okta.com/exkh8taf05g5Hi7nY0h7":                           {`MIIDpDCCAoygAwIBAgIGAV5hMcvsMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi05MzY3ODIxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMTcwOTA4MTExMjI3WhcNMjcwOTA4MTExMzI2WjCBkjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtOTM2NzgyMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq82ohLSDnu8vfqG9OB3WeCTDJWaXgWptXXfElLoVDAxzDsqGWTgS+omUGRzZcrCfrCzSGhhu6/DUM/22xZU5huI18WHfidOf3OBUXnQgHnIV7zRDwhhz5FqvvaZlqBa52koC1QUWb98RFzfLgplrMFKEXQAKabZY2JwWCG/xQrojoL1YjGpKM2vMHZ4kKrg/v4xVtAQQuxqJ3he6aD0icztsJ77jR3EbID9t4DpTvGkNK7GPXK9lt/XIUgX5Mz6BMCXD9emynzkOcEbWysCmwu051YcFAsdvhujPFuqUS2LWgKGMsiS8prP11A4w1Tv0pHfdDfg+k8B5YdjcrUV14QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB0hHHSfSzOZoSVVXwSDTuPb8kUcO/C7VRF3u7Cn+Xaao++UO5Li70LITQvgvYDsF1gv0YuqBRFOXh8HXy3WbYO8W73BiQ7YXrzM5eVC8ynIWKsVaBMNR3GKavE3eGrdB8N22fqnpx1y+Yviiv/9rFg6QWUC9LRSWdbtzQQADvJGz2cUZeYcQCePDcBJuyPYWCWlFzz/oIeltkbZzhGTH2pecuFb/7FTUwejUTPR9cSld1uRe+ttXO9OcpV6HTD3gQy3YEHUFzmMVK2EnCCmudAv/MjKVUNns6xxEbyOT72ysaH03L6O3HXmeXE3m6aUUeobaT7Zt5DfoYqpBg+UeuK`},
	"https://ec2amaz-uo93uqn.effective-software.com/adfs/services/trust": {`MIIDCDCCAfCgAwIBAgIQRsVLO9XksKpKs5V++Fis4TANBgkqhkiG9w0BAQsFADBAMT4wPAYDVQQDEzVBREZTIFNpZ25pbmcgLSBlYzJhbWF6LXVvOTN1cW4uZWZmZWN0aXZlLXNvZnR3YXJlLmNvbTAeFw0xOTAzMTQwODQ5MDJaFw0yMDAzMTMwODQ5MDJaMEAxPjA8BgNVBAMTNUFERlMgU2lnbmluZyAtIGVjMmFtYXotdW85M3Vxbi5lZmZlY3RpdmUtc29mdHdhcmUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA90im5KNIirZr+/F7s7w43H5zoLS/9RR4jW1Wm9sbjnrLP/zMKK+rCOOzuDjYjsOxJ6h/5q2cSWT6R0/qBmkEEbWUgl0KoCA8SUeClvgO7CO2HN+eZL8pFcsSrBwOluWKaVhJ40pS1XTXhy9BcmtvvJYkpHKkweaE1GeLutFPWzpVV8lXSQrzKvFLDFSAGmNhBPE1F7psEXO90ahofmkFRAYcW+8dpc8zjr3Qzuep68JCBkIB8zBKCEAh7w7Z47yUFOBq+NDX1S9ri5tQ3PEsUp/5pbhc/LmEpKhB7oPl4nrDjJ3IXXtASY2myt4Eo+D80gw9H9+zrhhAGcv9iZZjgQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCHtooDQT5hszZNmszKkA6r7ouyfONL2KIhA3RFwvjUYmmg/IQDjdofqeCfHPeNDr3sEc9Q8ynYvmifl6MmHJhqBhJbQTs/AVocqj9bTn11KS0XWzfd3m3EWgQL9djS9miKULFrURCOn16wnEft0hhoyxcd0OpIfrDwVBTW+GHgQhgVlMjGj/M/wULJuPpn5Fe5+Zomd7Iv31Prsj3jjTFlmOh4jups1wkECfJOtNhOj76b9EIp6vDpIgtQ4WJdvHzc5vQwKx91ONUIHut+K6SbTh2Oy9WYG1I8QuZI7wpE47wEWa3chpFEgl+GUgiyrlOtDCRigudPL7jvMQmF/5bQ`},
}

func myjar(issuer string) *x509.CertPool {
	pem := certs[issuer]
	pool := x509.NewCertPool()
	for _, p := range pem {
		bytes, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			panic(err)
		}
		c, err := x509.ParseCertificate(bytes)
		if err != nil {
			panic(err)
		}

		// a cheat, so that we can read old certificate
		if c.NotAfter.Before(acceptTime) {
			acceptTime = c.NotAfter.Add(-24 * time.Hour)
		}

		pool.AddCert(c)
	}
	return pool
}
