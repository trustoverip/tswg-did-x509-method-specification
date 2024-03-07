## Example

`did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:O:My%20Organisation`

In this example, the identifier pins to a certificate authority using the SHA-256 certificate hash and uses the `subject` policy to express criteria which a leaf certificate's subject must fulfill. This identifier will match any certificate chains with matching leaf certificate subject fields and a matching intermediate or root CA certificate.
