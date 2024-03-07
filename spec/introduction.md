[//]: # (Pandoc Formatting Macros)

[//]: # (::: introtitle)

[//]: # (Introduction)

[//]: # (:::)

## Introduction

The RWOT11 workshop outlined the need for hybrid solutions that combine X.509 certificates with DIDs: ["Analysis of hybrid wallet solutions - Implementation options for combining x509 certificates with DIDs and VCs"](https://github.com/WebOfTrustInfo/rwot11-the-hague/blob/master/advance-readings/hybrid_wallet_solutions_x509_DIDs_VCs.md).

The `did:x509` method takes a simple approach that does not introduce additional infrastructure. Creating and resolving a `did:x509` is a local operation. It relies on X.509 chain validation and matches elements contained in the DID to certificate properties within the chain.

The main difference to other DID methods is that `did:x509` requires a certificate chain to be passed using a new [DID resolution option](https://www.w3.org/TR/did-core/#did-resolution-options) `x509chain` while resolving a DID. This certificate chain is typically embedded in the signing envelope, for example within the `x5c` header parameter of JWS/JWT documents.

This work is derived from a draft `did:x509` method specification published by Maik Riechert and Antoine Delignat-Lavaud of Microsoft which is published here: https://github.com/microsoft/did-x509.
