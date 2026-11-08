"""Read Google Authenticator's ``otpauth-migration://`` exports.

The Android/iOS app exports its accounts as one or more QR codes containing::

    otpauth-migration://offline?data=<base64 protobuf>

where the protobuf is::

    message MigrationPayload {
      repeated OtpParameters otp_parameters = 1;
      int32 version = 2;
      int32 batch_size = 3;
      int32 batch_index = 4;
      int32 batch_id = 5;
    }
    message OtpParameters {
      bytes secret = 1;
      string name = 2;
      string issuer = 3;
      Algorithm algorithm = 4;   // 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
      DigitCount digits = 5;     // 1 six, 2 eight
      OtpType type = 6;          // 1 HOTP, 2 TOTP
      int64 counter = 7;
    }

Only the handful of wire types that format uses are implemented, so this stays
dependency-free instead of pulling in ``protobuf``.
"""

from __future__ import annotations

import base64
import binascii
import subprocess
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, quote_plus, unquote, urlparse

ALGORITHMS = {1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIGITS = {1: 6, 2: 8}
TYPES = {1: "hotp", 2: "totp"}

MIGRATION_PREFIX = "otpauth-migration://"


class MigrationError(RuntimeError):
    """The payload is not a readable otpauth-migration export."""


@dataclass(frozen=True)
class Account:
    issuer: str
    name: str
    secret: str          # base32, no padding
    algorithm: str = "SHA1"
    digits: int = 6
    kind: str = "totp"   # totp | hotp
    counter: int = 0

    @property
    def title(self) -> str:
        if self.issuer and self.name:
            return f"{self.issuer}: {self.name}"
        return self.name or self.issuer or "imported"

    def otpauth_uri(self) -> str:
        """The URI KeePassXC expects in an entry's ``otp`` attribute."""
        label = f"{self.issuer}:{self.name}" if self.issuer else self.name
        params = [("secret", self.secret)]
        if self.issuer:
            params.append(("issuer", self.issuer))
        if self.kind == "hotp":
            params.append(("counter", str(self.counter)))
        else:
            params.append(("period", "30"))
        params.append(("algorithm", self.algorithm))
        params.append(("digits", str(self.digits)))
        query = "&".join(f"{k}={quote_plus(str(v))}" for k, v in params)
        return f"otpauth://{self.kind}/{quote(label, safe='')}?{query}"


# -- minimal protobuf reading -------------------------------------------

def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise MigrationError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise MigrationError("varint too long")


def _fields(buf: bytes):
    """Yield ``(field_number, wire_type, value)`` for one message."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        number, wire = key >> 3, key & 0x7
        if wire == 0:
            value, pos = _read_varint(buf, pos)
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            value = buf[pos:pos + length]
            if len(value) != length:
                raise MigrationError("truncated length-delimited field")
            pos += length
        elif wire == 1:
            value = buf[pos:pos + 8]
            pos += 8
        elif wire == 5:
            value = buf[pos:pos + 4]
            pos += 4
        else:
            raise MigrationError(f"unsupported protobuf wire type {wire}")
        yield number, wire, value


def _parse_otp_parameters(buf: bytes) -> Account:
    secret = b""
    name = issuer = ""
    algorithm, digits, kind, counter = "SHA1", 6, "totp", 0
    for number, _wire, value in _fields(buf):
        if number == 1:
            secret = value
        elif number == 2:
            name = value.decode("utf-8", "replace")
        elif number == 3:
            issuer = value.decode("utf-8", "replace")
        elif number == 4:
            algorithm = ALGORITHMS.get(value, "SHA1")
        elif number == 5:
            digits = DIGITS.get(value, 6)
        elif number == 6:
            kind = TYPES.get(value, "totp")
        elif number == 7:
            counter = value
    if not secret:
        raise MigrationError("account without a secret")
    encoded = base64.b32encode(secret).decode("ascii").rstrip("=")
    return Account(issuer=issuer.strip(), name=name.strip(), secret=encoded,
                   algorithm=algorithm, digits=digits, kind=kind, counter=counter)


def decode_payload(data: str) -> tuple[list[Account], int]:
    """Decode the base64 ``data`` parameter into accounts and a batch index."""
    data = unquote(data.strip())
    padding = "=" * (-len(data) % 4)
    try:
        raw = base64.b64decode(data + padding, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise MigrationError(f"payload is not base64: {exc}") from exc
    accounts: list[Account] = []
    batch_index = 0
    for number, _wire, value in _fields(raw):
        if number == 1:
            accounts.append(_parse_otp_parameters(value))
        elif number == 4:
            batch_index = value
    if not accounts:
        raise MigrationError("payload contains no accounts")
    return accounts, batch_index


def decode_uri(uri: str) -> tuple[list[Account], int]:
    """Decode a full ``otpauth-migration://offline?data=...`` URI."""
    uri = uri.strip()
    if not uri.lower().startswith(MIGRATION_PREFIX):
        raise MigrationError("not an otpauth-migration:// URI")
    query = parse_qs(urlparse(uri).query)
    if "data" not in query:
        raise MigrationError("URI has no ?data= parameter")
    return decode_payload(query["data"][0])


# -- getting the URI out of a screenshot --------------------------------

def read_qr(image: str) -> str:
    """Read a QR code with zbarimg and return its text."""
    try:
        proc = subprocess.run(
            ["zbarimg", "--quiet", "--raw", image],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError as exc:
        raise MigrationError(
            "zbarimg is not installed; install zbar, or pass the decoded "
            "otpauth-migration:// string with --data"
        ) from exc
    text = (proc.stdout or "").strip()
    if proc.returncode != 0 or not text:
        detail = (proc.stderr or "").strip()
        raise MigrationError(f"no QR code found in {image}" + (f": {detail}" if detail else ""))
    return text


def secret_of(uri: str) -> str:
    """The ``secret`` parameter of any otpauth URI, or ""."""
    query = parse_qs(urlparse(uri).query)
    return (query.get("secret") or [""])[0]
