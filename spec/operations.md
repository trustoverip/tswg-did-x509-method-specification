## Operations

### Create

Creating a `did:x509` identifier is a local operation. The DID must be constructed according to the syntax rules in the previous sections. No other actions are required.

When constructing a `did:x509`, the first step is to determine what constitutes a logical identity within a given certificate authority. Concretely, which certificate fields does an authority use to uniquely represent an identity. After that, one or more matching policies must be chosen that allow to express such an identity as faithfully as possible.

As an example, a certificate authority may exclusively use email addresses as a way to separate identities, and it may use the SAN extension to store the email address. In that case, the `did:x509` identifier should be constructed using the `san` policy, for example, `did:x509:0:sha256:<ca-fingerprint>::san:email:bob%40example.com`. The certificate may contain other information about the identity, like full name and address, but the primary field that uniquely identifies the identity in this case is just the email address.

In other cases, an authority may not include email addresses at all and instead rely on a specific set of subject fields to separate identities. In that case, the `subject` policy should be used.

In yet other cases, authorities may assign unique numbers or other types of stable identifiers to logical identities. Typically, this is done to have a stable reference even if a person changes their name or email address.

In all cases, the goal is to craft a `did:x509` that is both stable yet not too loose in its policies. An example of a loose `did:x509` may be to use the `subject` policy and only include the `O` field without location fields like country (`C`) or state/locality (`ST`). See also the Security and Privacy Considerations section.

Finally, whether a `did:x509` should pin to an intermediate CA instead of a root CA (via the certificate fingerprint) depends on whether there is value in distinguishing between them. Pinning to an intermediate CA typically means that the lifetime of the `did:x509` will be shorter, since intermediate CA certificates typically have a shorter validity period than root CA certificates.

### Read

::: issue 
https://github.com/trustoverip/tswg-did-x509-method-specification/issues/10: Add discussion on timestamp of signature issuance relative to cert validity
:::

The Read operation takes as input a DID to resolve, together with the `x509chain` DID resolution option.

The following steps must be used to generate a corresponding DID document:

1. Decode the `x509chain` resolution option value into individual certificates by splitting the string on `","` and base64url-decoding each resulting string. The result is a list of DER-encoded certificates that can be loaded in standard libraries. Fail if the list contains fewer than two certificates.

2. Check whether the list of certificates form a valid certificate chain using the [RFC 5280 certification path validation](https://www.rfc-editor.org/rfc/rfc5280#section-6) procedures with the last certificate in the chain as trust anchor. If any extension, excluding the basic constraints and key usage extensions, is marked critical but is not part of the JSON data model, fail.

3. If required by the application, check whether any certificate in the chain is revoked (using CRL, OCSP, or other mechanisms).

4. Apply any further application-specific checks, for example disallowing insecure certificate signature algorithms.

5. Map the certificate chain to the JSON data model.

6. Check whether the DID is valid against the certificate chain in the JSON data model according to the Rego policy (or equivalent rules) defined in this document.

7. Extract the public key of the first certificate in the chain.

8. Convert the public key to a JSON Web Key.

9. Create the following partial DID document:

```json
{
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
    ],
    "id": "<DID>",
    "verificationMethod": [{
        "id": "<DID>#key-1",
        "type": "JsonWebKey2020",
        "controller": "<DID>",
        "publicKeyJwk": {
            // JSON Web Key
        }
    }]
}
```

10. If the first certificate in the chain has the key usage bit position for `digitalSignature` set or is missing the key usage extension, add the following to the DID document:

```json
{
    "assertionMethod": ["<DID>#key-1"]
}
```

11. If the first certificate in the chain has the key usage bit position for `keyAgreement` set or is missing the key usage extension, add the following to the DID document:

```json
{
    "keyAgreement": ["<DID>#key-1"]
}
```

12. If the first certificate in the chain includes the key usage extension but has neither `digitalSignature` nor `keyAgreement` set as key usage bits, fail.

13. Return the complete DID document.

### Update

This DID Method does not support updating the DID Document, assuming a fixed certificate chain. However, the public key included in the DID Document varies depending on the certificate chain that was used as input to the DID resolution process. Typically, multiple chains, in particular leaf certificates, are valid for a given `did:x509`.

### Deactivate

This DID Method does not support deactivating the DID. However, if the certificate authority revokes all certificates for the matching DID (or they expire) and does not issue new certificates matching the same DID, then this can be considered equivalent to deactivation of the DID, though there is no technical guarantee in this case and the certificate authority can revert its decision.
