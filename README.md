# SAML claim validation library

The SAML authentication protocol [1] allow users to authenticate on another server than the one
running the desired service, and provide a claim of identity to the service provider.

This library provides a simple Check mechanism to ensure that the claim provided by a user is indeed
valid (cryptographically signed by the certificate). Stricter validation mechanisms can be added.

## Goals (and non-goals)

SAML is an, shall we say, enterprise protocol (for example, the core specification clocks at 80+
pages, but actually refers to other specifications such as XML digital signature, which itself
refers to XPath, …); it is therefore very hard to provide a small, solid trusted code base that
would cover the full specification.

This package therefore does NOT try to match the specification, but instead to accept
implementations seen “in the wild”. Instead, the focus is to provide a safe library with correct
cryptography, safety against XML vulnerability (we do not expand XML directives, or understand the
full XPath syntax) and sanity for side-channels exploits (although those are very, very, very hard
to avoid when using XML digital signatures).

## Contributing

We welcome patches adressing security vulnerabilities, increasing the robustness of the test suite
or adding support for a “common enough” identity provider — keeping the package tidy and small for
auditability is paramount, and don’t take it personally if we are a bit conservative.

[1] https://developer.okta.com/docs/concepts/saml/
