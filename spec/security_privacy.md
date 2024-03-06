## Security and privacy considerations

### Identifier ambiguity

This DID method maps characteristics of X.509 certificate chains to identifiers. It allows a single identifier to map to multiple certificate chains, giving the identifier stability across the expiry of individual chains. However, if the policies used in the identifier are chosen too loosely, the identifier may match too wide a set of certificate chains. This may have security implications as it may authorize an identity for actions it was not meant to be authorized for.

To mitigate this issue, the certificate authority should publish their expected usage of certificate fields and indicate which ones constitute a unique identity, versus any additional fields that may be of an informational nature. This will help users create an appropriate `did:x509` as well as consumers of signed content to decide whether it is appropriate to trust a given `did:x509`.

### X.509 trust stores

Typically, a verifier trusts an X.509 certificate by applying [chain validation](https://www.rfc-editor.org/rfc/rfc5280#section-6) (RFC 5280) using a set of certificate authority (CA) certificates as trust store, together with additional application-specific policies.

This DID method does not require an X.509 trust store but rather relies on verifiers either trusting an individual DID directly or using third-party endorsements for a given DID, like [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/), to establish trust.

By layering this DID method on top of X.509, verifiers are free to use traditional chain validation (for example, verifiers unaware of DID), or rely on DID as an ecosystem to establish trust.
