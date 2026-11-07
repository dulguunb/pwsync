"""TOTP normalisation shared by both vaults.

Bitwarden accepts either a bare base32 secret or a full ``otpauth://`` URI in
``login.totp``. KeePassXC only generates codes from an ``otpauth://`` URI in the
entry's ``otp`` attribute: a bare secret is stored but silently ignored, and
``keepassxc-cli show --totp`` reports "no TOTP set up".

Every TOTP value read from either vault is therefore canonicalised to a URI, so
the same secret produces the same content hash on both sides and the codes work
in both applications.
"""

from __future__ import annotations

from urllib.parse import quote

# RFC 4648 base32, which is what every authenticator uses for TOTP seeds.
BASE32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
DEFAULT_PARAMS = "period=30&digits=6&algorithm=SHA1"
MIN_SECRET_LENGTH = 8


def normalize(value: str, label: str = "") -> str:
    """Return ``value`` as an ``otpauth://totp`` URI.

    An empty value returns ``""``. A value that already is a URI, or that does
    not look like a base32 secret, is returned unchanged so nothing is lost.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if raw.lower().startswith("otpauth://"):
        return raw
    secret = "".join(char for char in raw.upper() if char in BASE32_ALPHABET)
    if len(secret) < MIN_SECRET_LENGTH:
        return raw
    name = quote(label.strip() or "pwsync", safe="")
    return f"otpauth://totp/{name}?secret={secret}&{DEFAULT_PARAMS}"
