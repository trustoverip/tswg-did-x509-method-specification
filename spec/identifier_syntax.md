## Identifier Syntax

The `did:x509` ABNF definition can be found below, which uses the syntax in [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234.html) and the corresponding definitions for `ALPHA` and `DIGIT`. The [W3C DID v1.0 specification](https://www.w3.org/TR/2022/REC-did-core-20220719/) contains the definition for `idchar`.

```abnf
did-x509           = "did:" method-name ":" method-specific-id
method-name        = "x509"
method-specific-id = version ":" ca-fingerprint-alg ":" ca-fingerprint 1*("::" policy-name ":" policy-value)
version            = 1*DIGIT
ca-fingerprint-alg = "sha256" / "sha384" / "sha512"
ca-fingerprint     = base64url
policy-name        = 1*ALPHA
policy-value       = *(1*idchar ":") 1*idchar
base64url          = 1*(ALPHA / DIGIT / "-" / "_")
```

In this draft, version is `0`.

`ca-fingerprint-alg` is one of `sha256`, `sha384`, or `sha512`.

`ca-fingerprint` is `chain[i].fingerprint[ca-fingerprint-alg]` with i > 0, that is, either an intermediate or root CA certificate.

`policy-name` is a policy name and `policy-value` is a policy-specific value. 

`::` is used to separate multiple policies from each other.

The following sections define the policies and their policy-specific syntax.

Validation of policies is formally defined using [Rego policies](https://www.openpolicyagent.org/docs/latest/policy-language/), though there is no expectation that implementations use Rego.

The input to the Rego engine is the JSON document `{"did": "<DID>", "chain": <CertificateChain>}`.

Core Rego policy:

```rego
import future.keywords.if
import future.keywords.in

parse_did(did) := [ca_fingerprint_alg, ca_fingerprint, policies] if {
    prefix := "did:x509:0:"
    startswith(did, prefix) == true
    rest := trim_prefix(did, prefix)
    parts := split(rest, "::")
    [ca_fingerprint_alg, ca_fingerprint] := split(parts[0], ":")
    policies_raw := array.slice(parts, 1, count(parts))
    policies := [y |
        some i
        s := policies_raw[i]
        j := indexof(s, ":")
        y := [substring(s, 0, j), substring(s, j+1, -1)]
    ]
}

valid if {
    [ca_fingerprint_alg, ca_fingerprint, policies] := parse_did(input.did)
    ca := [c | some i; i != 0; c := input.chain[i]]
    ca[_].fingerprint[ca_fingerprint_alg] == ca_fingerprint
    valid_policies := [i |
        some i
        [name, value] := policies[i]
        validate_policy(name, value)
    ]
    count(valid_policies) == count(policies)
}
```

The overall Rego policy is assembled by concatenating the core Rego policy with the Rego policy fragments in the following sections, each one defining a `validate_policy` function.

### Percent-encoding

Some of the policies that are defined in subsequent sections require values to be percent-encoded. Percent-encoding is specified in [RFC 3986 Section 2.1](https://www.rfc-editor.org/rfc/rfc3986#section-2.1). All characters that are not in the allowed set defined below must be percent-encoded:

```abnf
allowed = ALPHA / DIGIT / "-" / "." / "_"
```

Note that most libraries implement percent-encoding in the context of URLs and do NOT encode `~` (`%7E`).

### `subject` policy

```abnf
policy-name     = "subject"
policy-value    = key ":" value *(":" key ":" value)
key             = label / oid
value           = 1*idchar
label           = "CN" / "L" / "ST" / "O" / "OU" / "C" / "STREET"
oid             = 1*DIGIT *("." 1*DIGIT)
```

`<key>:<value>` are the subject name fields in `chain[0].subject` in any order. Field repetitions are not allowed. Values must be percent-encoded.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:L:San%20Francisco:O:GitHub%2C%20Inc.`

Rego policy:
```rego
validate_policy(name, value) := true if {
    name == "subject"
    items := split(value, ":")
    count(items) % 2 == 0
    subject := {k: v |
        some i
        i % 2 == 0
        k := items[i]
        v := urlquery.decode(items[i+1])
    }
    count(subject) >= 1
    object.subset(input.chain[0].subject, subject) == true
}
```

### `san` policy

```abnf
policy-name     = "san"
policy-value    = san-type ":" san-value
san-type        = "email" / "dns" / "uri"
san-value       = 1*idchar
```

`san-type` is the SAN type and must be one of `email`, `dns`, or `uri`. Note that `dn` is not supported.

`san-value` is the SAN value, percent-encoded.

The pair [`<san_type>`, `<san_value>`] is one of the items in `chain[0].extensions.san`.

Example: 

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::san:email:bob%40example.com`

Rego policy:

```rego
validate_policy(name, value) := true if {
    name == "san"
    [san_type, san_value_encoded] := split(value, ":")
    san_value := urlquery.decode(san_value_encoded)
    [san_type, san_value] == input.chain[0].extensions.san[_]
}
```

### `eku` policy

```abnf
policy-name  = "eku"
policy-value = eku
eku          = oid
oid          = 1*DIGIT *("." 1*DIGIT)
```

`eku` is one of the OIDs within `chain[0].extensions.eku`.

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13`

Rego policy:

```rego
validate_policy(name, value) := true if {
    name == "eku"
    value == input.chain[0].extensions.eku[_]
}
```

### `fulcio-issuer` policy

```abnf
policy-name   = "fulcio-issuer"
policy-value  = fulcio-issuer
fulcio-issuer = 1*idchar
```

`fulcio-issuer` is `chain[0].extensions.fulcio_issuer` without leading `https://`, percent-encoded. 

Example:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:accounts.google.com::san:email:bob%40example.com`

Example 2:

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::fulcio-issuer:token.actions.githubusercontent.com::san:uri:https%3A%2F%2Fgithub.com%2Focto-org%2Focto-automation%2F.github%2Fworkflows%2Foidc.yml%40refs%2Fheads%2Fmain`

Rego policy:

```rego
validate_policy(name, value) := true if {
    name == "fulcio-issuer"
    suffix := urlquery.decode(value)
    concat("", ["https://", suffix]) == input.chain[0].extensions.fulcio_issuer
}
```
