## DID resolution options

::: issue 
https://github.com/trustoverip/tswg-did-x509-method-specification/issues/6: Planned review by of this section by task force
:::

This DID method introduces a new DID resolution option called `x509chain`:

Name: `x509chain`

Value type: string

The value is constructed as follows:

1. Encode each certificate `C` that is part of the chain as the string `b64url(DER(C))`.

2. Concatenate the resulting strings in order, separated by comma `","`.
