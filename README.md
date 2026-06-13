![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# OWID

Simple cryptographically auditable identifiers and processors implemented in
Python.

## Overview

An Open Web Id (OWID) records that the entity operating a domain captured or
generated a payload at a date and time, together with an ECDSA signature over
the OWID and any other OWIDs it was signed with. OWIDs chain together to form
verifiable trees. The curve is NIST P-256 (also known as secp256r1 or
prime256v1) and the hash is SHA-256.

Read the [OWID project](https://github.com/SWAN-community/owid) to learn more
about the concepts before looking into this implementation. This package
creates, signs, serializes, and verifies OWIDs.

## Scope of this implementation

This package provides the core data structure, the binary and base 64 wire
format, the ECDSA signing and verification, a creator that binds a domain to a
signing key, and framework agnostic helpers for the well known end points. It
has no network access of its own, so retrieving a creator public key over HTTP
is left to the caller.

Version 3 is the current version produced for new OWIDs. Versions 1 and 2 are
deprecated and are supported for reading existing data only.

## Installation

The package targets Python 3.9 and later and depends on the
[cryptography](https://pypi.org/project/cryptography/) library.

Install from a checkout of this repository.

```
python -m pip install .
```

For development, install in editable mode.

```
python -m pip install -e .
```

## Usage

```python
from owid import Creator, Crypto, Owid

# The creator operates a domain and holds the signing keys.
crypto = Crypto.new()
creator = Creator("example.com", crypto)

# Create and sign an OWID with a payload.
owid = creator.sign_string("Hello World")

# Serialize to base 64 for storage or transmission.
encoded = owid.as_base64()

# Later, or elsewhere, decode and verify with the creator public key.
copy = Owid.from_base64(encoded)
public_pem = crypto.public_key_pem()
assert copy.verify_with_public_key(public_pem, [])
```

OWIDs chain together. To sign an OWID with another OWID covered by the same
signature, pass the others when signing and the same others, in the same
order, when verifying.

```python
root = creator.sign_string("root")
party = Owid(payload=b"party")
creator.sign_with_others(party, [root])

assert party.verify_with_crypto(crypto, [root])
assert not party.verify_with_crypto(crypto, [])
```

## Interface

`Owid`

- `from_base64(value)` and `from_byte_array(buffer)` parse a signed OWID.
- `as_base64()` and `as_byte_array()` serialize a signed OWID.
- `payload_as_string()` decodes the payload as UTF-8, replacing invalid bytes.
- `payload_as_printable()` returns the payload as lower case hexadecimal.
- `payload_as_base64()` returns the payload as a base 64 string.
- `verify_with_crypto(crypto, others)` and
  `verify_with_public_key(public_pem, others)` return True if the signature is
  valid. Pass an empty list for `others` when the OWID was signed on its own.
- `age_minutes()` returns the whole minutes elapsed since creation.

`Crypto`

- `new()` generates a P-256 key pair.
- `new_sign_only(private_pem)` imports a PKCS#8 or SEC1 private key PEM.
- `new_verify_only(public_pem)` imports an SPKI public key PEM.
- `sign_byte_array(data)` returns the 64 byte signature.
- `verify_byte_array(data, signature)` returns True if the signature is valid.
- `subject_public_key_info()` and `private_key_pem()` export the keys as PEM.

An empty or whitespace PEM is rejected with a clear message rather than an
opaque crypto error.

`Creator`

- `Creator(domain, crypto)` binds a domain to a signing crypto instance.
- `from_configuration(configuration)` builds a creator from a domain and a
  private key PEM.
- `sign(owid)` and `sign_with_others(owid, others)` set the domain, date, and
  version, then sign.
- `sign_string(value)` and `sign_bytes(value)` create and sign a new OWID.

`endpoints`

- `creator_path(version)` and `public_key_path(version)` return the well known
  paths.
- `creator_response(creator, name, contract_url)` returns the creator JSON
  with the `domain`, `name`, `publicKeySPKI`, and `contractURL` fields.
- `public_key_response(creator, format)` returns the public key PEM. The
  format must be `spki` or `pkcs`.

## Data structure notes

A signed OWID serializes to bytes in this order. Multi byte integers are
little endian unless stated otherwise.

| Field          | Bytes               | Description                                                  |
|----------------|---------------------|--------------------------------------------------------------|
| Version        | 1                   | The byte version of the OWID. Always the first byte.         |
| Domain         | length + 1          | Domain associated with the creator, null (0) terminated.     |
| Date           | 4 (2 for version 1) | Minutes elapsed since 2020-01-01 UTC as an unsigned integer. |
| Payload length | 4                   | Number of bytes that form the payload.                       |
| Payload        | variable            | Bytes that form the payload, if any.                         |
| Signature      | 64                  | ECDSA P-256 signature as the r and s values concatenated.    |

Version 1 stored the date as a two byte big endian count of hours since the
base date. Versions 2 and 3 store it as a four byte little endian count of
minutes. The base date is 2020-01-01T00:00:00 UTC.

The signature is the 64 byte concatenation of the 32 byte big endian r value
and the 32 byte big endian s value (IEEE P1363 format), not the ASN.1 DER form
that most libraries produce by default. The data covered by the signature is
this OWID without its signature, followed by the complete bytes, including the
signature, of each other OWID in the order given. The same others in the same
order must be supplied to verify as were supplied to sign.

An empty OWID is written as a single byte with value 0 and acts as a marker
for an absent optional OWID inside a larger byte array.

Base 64 decoding accepts input with or without trailing padding. Encoding
always emits padding.

## Testing

The tests use the standard library `unittest` and exercise the canonical wire
vectors, the cross language signed fixtures, the signing path, and the unit
behaviour of each module. Run them from the repository root.

```
python -m unittest discover
```

## License

Apache License 2.0. See the [LICENSE](LICENSE) file.
