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
signing key, framework agnostic helpers for the well known end points, and
the fetch of another creator's public key from its well known end point. The
core has no network access of its own. The one module that reaches the
network is `owid.public_key_fetch`, which uses the standard library `urllib`,
is imported only by a caller that asks for it, and takes a transport of the
caller's own where `urllib` is not the right client.

Version 3 is the current version produced for new OWIDs. Versions 1 and 2 are
deprecated and are supported for reading existing data only.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain carries
no length of its own, so the protocol alone is not an application input limit
for the complete envelope.

This package compares the declared payload length with the bytes actually
present before it sizes or copies the payload, so a large declaration without
the corresponding bytes is refused without ever allocating the declared size.
That refusal is `ParseStatus.BYTE_COUNT_MISMATCH` on a whole buffer read and
`ParseStatus.UNEXPECTED_END` on a framed one, for the reason given under
reading below. A matching large payload is not malformed merely because it is
large, and parsing work and memory use scale with the bytes actually present.

The domain ends at a zero terminator rather than at a declared length, so a
buffer whose terminator is missing or corrupted would otherwise be walked to
its end. This package stops that walk at `MAXIMUM_DOMAIN_LENGTH`, which
`owid/io.py` derives from the size limit in RFC 1035 section 2.3.4, and
refuses the buffer there. The cost of a domain field an attacker sized is
therefore fixed by that constant rather than by the length of the input, and
no domain a name server would accept is affected.

The same maximum binds the write, because a library that emits something it
cannot read moves the fault to the consumer. A `Creator` refuses a domain
longer than `MAXIMUM_DOMAIN_LENGTH` when the caller supplies it, before any
signing work is done, and the writer refuses one that reached an OWID by any
other route when the OWID is serialised. Both raise `OwidError` naming the
maximum, because a domain that long is a fault in the calling code rather than
data arriving from outside. A read reports the same finding as
`ParseStatus.INVALID_DOMAIN_ENCODING` instead of raising, as there the domain
came from whoever sent the bytes.

The in-memory APIs remain subject to Python object, address-space and
available-memory limits. Applications accepting untrusted OWIDs must choose
limits suitable for their use case and enforce them before buffering the
binary form or decoding Base64. An implementation capacity failure or an
application policy rejection is distinct from an invalid OWID, which is why
`ParseStatus.IMPLEMENTATION_CAPACITY_EXCEEDED` is a status of its own and the
same bytes may be readable somewhere with more room.

For transport input, limit the complete HTTP body or encoded envelope, and
allow for the domain and other OWID fields as well as the payload. After a
successful read, `len(result.owid.payload)` reports the actual payload size
without another copy and can be used for downstream policy. The reader cannot
choose either limit on behalf of the application.

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

Create a creator that holds the signing keys, create a signed OWID, serialize
it, then read it back later and verify it with the public key.

```python
from owid import Creator, Crypto, Owid

# The creator operates a domain and holds the signing keys.
crypto = Crypto.new()
creator = Creator("example.com", crypto)

# Creating and signing are one step, so an OWID never exists unsigned.
owid = creator.create_string("Hello World")

# Serialize to base 64 for storage or transmission.
encoded = owid.as_base64()

# Later, or elsewhere, read it back. Input from outside may be anything at
# all, so reading answers with a result rather than raising.
result = Owid.parse(encoded)
if result:
    public_pem = crypto.public_key_pem()
    assert result.owid.verify_with_public_key(public_pem, [])
else:
    # result.status names which of the expected problems it was, for example
    # ParseStatus.INVALID_BASE64 or ParseStatus.BYTE_COUNT_MISMATCH.
    reason = result.status.value
```

OWIDs chain together. Create one that covers others, and pass the same others,
in the same order, when verifying.

```python
root = creator.create_string("root")
party = creator.create(b"party", [root])

assert party.verify_with_crypto(crypto, [root])
assert not party.verify_with_crypto(crypto, [])
```

Where the difference between a signature that does not match and a check that
could not be made changes what your code should do, ask for the status rather
than a true or false answer. A key that cannot be read is reported as a fault
in the key and never as a forgery.

```python
from owid import SignatureStatus

status = owid.signature_status(crypto.public_key_pem())
if status is SignatureStatus.SIGNATURE_VALID:
    pass  # Genuine.
elif status is SignatureStatus.SIGNATURE_INVALID:
    pass  # The only status meaning the identifier should be distrusted.
else:
    # INVALID_KEY, VERIFICATION_ERROR and the rest mean the question could
    # not be answered, which is an operational fault rather than an attack.
    pass
```

## Verifying an identifier signed in an earlier week

Creators rotate their signing key, weekly in the case of the 51Degrees cloud,
so the key that is current when an identifier is checked is not the key that
signed the identifier unless the check happens in the same week. Verifying
anything older than a few days means asking for the key that was in force on
the date the identifier carries.

`owid.public_key_fetch` asks the creator for that key. The request is
`/owid/api/v{n}/public-key?date={minutes}&format=pkcs`, where the version in
the path is the version byte of the identifier being checked and the minutes
are counted from 2020-01-01 in the same way the identifier stores its date. A
creator that ignores the parameter returns its current key, so every
identifier it signed under an earlier key reads as not matching, which is why
a creator that rotates its key has to honour the date. Keys already fetched
are held against the URL they came from, which names the domain, the version
and the minute, up to 1024 of them before the store is emptied, and
`clear_cache()` empties it on demand. Each request waits at most ten seconds.

```python
from owid import SignatureStatus, public_key_fetch

# A creator whose key this example never actually asks for. The transport
# below stands in for the network and refuses, so the example shows the
# shape of the call and the status a key that cannot be obtained produces
# without touching a resolver or a proxy.
remote_creator = Creator("creator.invalid", Crypto.new())
remote = remote_creator.create_string("from another creator")

def unreachable(url, timeout):
    raise OSError("this example makes no request")

fetched = public_key_fetch.signature_status(
    remote, "https", transport=unreachable
)
if fetched is SignatureStatus.KEY_UNAVAILABLE:
    # The key could not be obtained, so the signature was never examined.
    # Only SIGNATURE_INVALID means the identifier should be distrusted.
    pass
assert fetched is SignatureStatus.KEY_UNAVAILABLE
```

A caller whose environment needs its own HTTP client passes a transport as
the last argument, being a callable that takes the URL and the timeout in
seconds, returns the response code and the body as bytes, and raises
`OSError` where no response could be obtained at all.

Where the whole published schedule is already held, `PublicKeySchedule`
chooses the key without any request. The rule is the one the cloud itself
applies, being the latest key whose start is at or before the date asked
about.

```python
from datetime import datetime, timezone
from owid import DatedPublicKey, PublicKeySchedule

last_week_pem = Crypto.new().public_key_pem()
schedule = PublicKeySchedule([
    DatedPublicKey(datetime(2026, 8, 24, tzinfo=timezone.utc), last_week_pem),
    DatedPublicKey(
        datetime(2026, 8, 31, tzinfo=timezone.utc), crypto.public_key_pem()
    ),
])
chosen = schedule.key_for(owid)
assert schedule.signature_status(owid) is SignatureStatus.SIGNATURE_VALID
```

Both examples are run by `tests/test_readme.py`, as the rest of the examples
in this file are. The fetch one runs against a creator domain in the reserved
`.invalid` name space, so it shows the status a key that cannot be obtained
produces, whilst the case where the key does arrive and the identifier
verifies is covered by `tests/test_public_key_fetch.py` against a stand in on
the loopback address.

The only date a key carries here is the date the key came into force. The
moment key material was generated is not that date and plays no part in the
choice, because a creator may generate several weeks of keys in one run, and
a key whose period has not started has signed nothing.

A creator that rotates its key answers the date parameter of its own public
key end point with `endpoints.public_key_response_at`, which returns the
status code and body for the request: the key in force at the date asked, the
key in force now for a request without a date or with a date later than now,
404 where no key is in force, and 400 where the date is not a count of
minutes.

## How an OWID comes into being

An OWID is only worth anything because it is signed, so a caller cannot build
one. An instance arrives by exactly two routes.

1. Reading bytes that were already a complete OWID, with `Owid.parse`,
   `Owid.parse_bytes` or `Owid.parse_prefix`.
2. `Creator.create` and `Creator.create_string`, which own the version, the
   domain, the date and the signature, and hand back a finished OWID.

Python cannot make a constructor private, so calling `Owid()` raises
`OwidError` naming the two routes instead. The payload and the signature are
handed out as copies and the fields are read only properties, because a parsed
OWID's signature covers its fields as they arrived, so code that could change
them afterwards would hold something whose signature no longer describes it.
There is no way to sign an OWID that already exists, as an unsigned OWID is
indistinguishable from a signed one to the code downstream of it and the
difference only surfaces later when a verification fails somewhere nobody is
watching.

## Reading data that may not be an OWID

An OWID is read from whatever a caller was handed, which on a public end point
means anything at all, so being malformed is an ordinary outcome rather than an
exceptional one. The parse methods report it instead of raising, because
raising costs the construction and unwinding of an exception for every bad
input and whoever sends the data chooses how often that happens.

Every read hands back a `ParseResult`, which is truthy on success and reports
the same three facts.

1. `result.ok`, whether it worked.
2. `result.owid`, the OWID on success and `None` on failure.
3. `result.status`, a `ParseStatus` naming the reason, which is
   `ParseStatus.PARSED` on success.

A result also carries `result.consumed`, the number of bytes the envelope
occupied, which a caller reading several OWIDs from one buffer uses to reach
the next one. Nothing is consumed when an envelope is refused, because a half
read one leaves a caller somewhere it cannot reason about.

The reasons a read can give are named by `ParseStatus`.

| Status | Meaning |
| ------ | ------- |
| `PARSED` | The bytes form a structurally valid OWID. This says nothing about the signature. |
| `MISSING_INPUT` | Nothing was supplied to parse. |
| `INVALID_INPUT_TYPE` | The input arrived in a form the surface cannot read, such as bytes where a base 64 string was wanted. |
| `INVALID_BASE64` | The string is not valid base 64, so there are no bytes to read. |
| `UNSUPPORTED_VERSION` | The first byte names a version this implementation does not know. |
| `UNEXPECTED_END` | The data stopped in the middle of a field. |
| `INVALID_DOMAIN_ENCODING` | The creator domain is not terminated, or is longer than the published maximum. |
| `BYTE_COUNT_MISMATCH` | The declared payload byte count disagrees with the bytes actually present. |
| `IMPLEMENTATION_CAPACITY_EXCEEDED` | The envelope is consistent but larger than this runtime can hold, or dated past the end of 9999 where `datetime` stops, so the same bytes may be readable elsewhere. |
| `ABSENT_NODE` | The one byte marker standing for a node that is not there. |
| `MALFORMED_ENVELOPE` | Malformed in a way none of the above describes. |

These names are the cross language vocabulary, so a failure means the same
thing whichever implementation read the bytes, and code matching on a status
never has to match on message text.

### The whole buffer contract and the framed contract

`Owid.parse` and `Owid.parse_bytes` require the value to be one whole OWID and
nothing else, because on those surfaces there is nothing else the bytes after
the envelope could belong to. The declared payload must leave exactly the
signature, so a byte after it is `ParseStatus.BYTE_COUNT_MISMATCH`.

`Owid.parse_prefix` reads one OWID from the front of a buffer that may carry
more after it and leaves the rest alone, because what follows may be the next
envelope rather than rubbish. It needs only the declared payload and the
signature to be present, and says nothing about the bytes beyond them. A frame
whose declaration runs past the bytes supplied is therefore
`ParseStatus.UNEXPECTED_END`, being data that stopped early rather than a
declaration disagreeing with data that is all present, which is the answer a
caller reading a source still arriving needs so that it can wait for more bytes
instead of giving up.

### The marker for a node that is absent

A single zero byte, written by `Owid.empty_to_buffer`, stands for an optional
OWID that is not there. Both reads report it as `ParseStatus.ABSENT_NODE` and
neither hands back an OWID, because the marker carries no domain, date, payload
or signature and so can never verify, and reading one as an identifier would be
the one way an instance with no signature could reach calling code. It is not
an unknown version, as version 0 is supported and meaningful, and it is not a
malformed frame either.

A framed read counts the marker's one byte as consumed, so a caller walking a
run of frames steps over an absent node and reaches the next envelope. A whole
buffer read consumes nothing, as there the marker on its own is the whole of
what was supplied.

```python
from owid import Owid, ParseStatus

# A buffer holding one OWID, a node that is absent, then another OWID.
buffer = bytearray()
creator.create_string("first").to_buffer(buffer)
Owid.empty_to_buffer(buffer)
creator.create_string("second").to_buffer(buffer)

data = bytes(buffer)
payloads = []
while data:
    frame = Owid.parse_prefix(data)
    if frame:
        payloads.append(frame.owid.payload_as_string())
    elif frame.status is not ParseStatus.ABSENT_NODE:
        break
    data = data[frame.consumed:]

assert payloads == ["first", "second"]
```

Reading is not verification. A successfully read OWID is structurally valid and
nothing more, and whether its signature is genuine is a separate question with
a separate answer.

## Interface

`Owid`

- `parse(value)` reads a complete OWID from its base 64 form.
- `parse_bytes(buffer)` reads a complete OWID from a buffer holding exactly
  one.
- `parse_prefix(buffer)` reads one OWID from the front of a buffer that may
  carry more after it.
- `version`, `domain`, `date`, `payload` and `signature` are read only
  properties.
- `as_base64()` and `as_byte_array()` serialize a signed OWID, and
  `to_buffer(buffer)` appends it to a `bytearray`.
- `empty_to_buffer(buffer)` writes the one byte marker for a node that is not
  there.
- `payload_as_string()` decodes the payload as UTF-8, replacing invalid bytes.
- `payload_as_printable()` returns the payload as lower case hexadecimal.
- `payload_as_base64()` returns the payload as a base 64 string.
- `verify_with_crypto(crypto, others)` and
  `verify_with_public_key(public_pem, others)` return True if the signature is
  valid. Pass an empty list for `others` when the OWID was signed on its own.
- `signature_status(public_pem, others)` answers the same question with a
  `SignatureStatus`, which keeps a signature that does not match apart from a
  check that could not be made at all.
- `age_minutes()` returns the whole minutes elapsed since creation.

`ParseResult`

- `ok`, `owid`, `status` and `consumed`, described under reading above. The
  result is truthy when `ok` is True, so `if result:` reads the way Python
  reads.

`ParseStatus` and `SignatureStatus`

- The named reasons a read or a signature check reports. Both are enumerations
  whose `value` is the cross language name, for example `"ByteCountMismatch"`.

`Crypto`

- `new()` generates a P-256 key pair.
- `new_sign_only(private_pem)` imports a PKCS#8 or SEC1 private key PEM.
- `new_verify_only(public_pem)` imports an SPKI public key PEM.
- `sign_byte_array(data)` returns the 64 byte signature.
- `verify_byte_array(data, signature)` returns True if the signature is valid.
- `subject_public_key_info()` and `private_key_pem()` export the keys as PEM,
  and `public_key_pem()` is an alias of the first of those.
- `can_sign()` and `can_verify()` report which keys the instance holds.

An empty or whitespace PEM is rejected with a clear message rather than an
opaque crypto error.

`Creator`

- `Creator(domain, crypto)` binds a domain to a signing crypto instance.
- `from_configuration(configuration)` builds a creator from a domain and a
  private key PEM.
- `create(value, others)` creates and signs a new OWID carrying the bytes,
  covering any others with the same signature.
- `create_string(value)` does the same with the UTF-8 bytes of a string.

`endpoints`

- `creator_path(version)` and `public_key_path(version)` return the well known
  paths.
- `creator_response(creator, name, contract_url)` returns the creator JSON
  with the `domain`, `name`, `publicKeySPKI`, and `contractURL` fields.
- `public_key_response(creator, format)` returns the public key PEM. The
  format must be `spki` or `pkcs`.
- `public_key_response_at(schedule, format, date, now=None)` returns the
  status code and body for a creator that rotates its key, choosing from a
  `PublicKeySchedule` the way the specification requires.

`public_key_fetch`

- `public_key_url(owid, scheme)` builds the request, naming the version of the
  OWID and the minute the OWID was signed.
- `public_key_pem(owid, scheme, transport=None)` returns the key, raising
  `PublicKeyFetchError`, which carries the status to report, the domain and
  the response code.
- `signature_status(owid, scheme, others=None, transport=None)` answers with
  the status, so a key that could not be fetched is `KEY_UNAVAILABLE`, one
  that could not be read is `INVALID_KEY`, and neither is mistaken for a
  signature that does not match. `verify` takes the same arguments and
  answers True only for `SIGNATURE_VALID`.
- `clear_cache()` empties the keys already fetched.

`PublicKeySchedule` and `DatedPublicKey`

- `PublicKeySchedule(keys)` takes the keys in any order.
- `key_in_force(date)` and `key_for(owid)` return the latest key whose start
  is at or before the date, or the date of the OWID, and None where the
  schedule does not reach back that far.
- `current()` returns the key in force now, and `last()` the key with the
  latest start, which for a schedule published ahead of time is usually a
  key that has not begun. `signature_status(owid, others=None)` chooses the
  key and answers with the status, and `verify` answers True only for
  `SIGNATURE_VALID`.
- `DatedPublicKey(starts_at, public_key_pem)` is one key and the date the key
  came into force, both read only. A naive datetime is read as UTC.

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

A single byte with value 0 is the marker for an absent optional OWID inside a
larger byte array, written by `Owid.empty_to_buffer` and reported by both reads
as `ParseStatus.ABSENT_NODE`, covered under reading above.

The two reads differ in three answers and agree everywhere else. A whole buffer
read requires the declared payload to leave exactly the signature, so a byte
after it is `ParseStatus.BYTE_COUNT_MISMATCH`, while a framed read requires
only that the payload and the signature are present and says nothing about what
follows. A frame whose declared payload runs past the bytes supplied is
`ParseStatus.UNEXPECTED_END`, so `ParseStatus.BYTE_COUNT_MISMATCH` is reachable
only on the whole buffer read where every byte is present by definition. A
framed read counts the marker's one byte as consumed and a whole buffer read
counts nothing.

Base 64 decoding accepts input with or without trailing padding. Encoding
always emits padding.

## Testing

The tests use the standard library `unittest` and exercise the canonical wire
vectors, the cross language signed fixtures, the signing path, and the unit
behaviour of each module. `tests/test_parse_contract.py` holds the cross
language status matrix, being the reasons a read reports and the proof that an
OWID cannot be held unsigned. `tests/test_readme.py` runs the Python examples
in this file in the order they appear, so documentation naming a method that
does not exist fails the build. `tests/test_public_key_fetch.py` drives the
real fetch against a stand in for a creator's public key end point on the
loopback address, serving the published 51d.es schedule, and
`tests/test_public_key_schedule.py` checks the choice of key against a genuine
identifier the 51Degrees cloud issued on 4 September 2026. Run them from the
repository root.

```
python -m unittest discover
```

## License

Apache License 2.0. See the [LICENSE](LICENSE) file.
