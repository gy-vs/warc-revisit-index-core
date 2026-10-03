"""WARC payload/block digest handling.

WARC digests look like ``sha1:2H7KK7FHQ3W...`` (RFC 3548 base32, no padding)
or ``sha1:hex:...``; plain base32/hex/Base64 blobs without an algorithm
prefix appear in the wild as well.  This module normalises them into a
``algo:encoded-value`` string that is safe to store and compare, and provides
a streaming hasher so payloads never have to be held in memory.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from .errors import UnknownDigestError

# base32 alphabet without padding, as used by WARC Payload-Digest
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Algorithm name normalisation: WARC label -> hashlib name
_ALGO_ALIASES = {
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha512": "sha512",
    "sha-512": "sha512",
    "md5": "md5",
}


@dataclass(frozen=True, slots=True)
class Digest:
    """A parsed WARC digest value."""

    algo: str
    """hashlib algorithm name, e.g. ``"sha1"`` (lower-cased)"""
    value: str
    """canonical (upper-case base32) encoding of :attr:`digest_bytes`"""
    raw: str
    digest_bytes: bytes = b""

    def __str__(self) -> str:
        return f"{self.algo}:{self.value}"

    @property
    def hexdigest(self) -> str:
        return self.digest_bytes.hex()

    def matches(self, other: "Digest") -> bool:
        # Compare on raw bytes so base32 and hex spellings are equivalent.
        if self.algo != other.algo:
            return False
        return self.digest_bytes == other.digest_bytes


def _decode_b32(text: str) -> bytes:
    pad = "=" * ((8 - len(text) % 8) % 8)
    return base64.b32decode(text + pad, casefold=True)


def _looks_like(text: str, alphabet: set[str]) -> bool:
    return bool(text) and all(c in alphabet for c in text)


def parse_digest(raw: str | bytes | None) -> Digest | None:
    """Parse a WARC digest header value.

    Returns ``None`` for ``None`` / empty input.  Raises
    :class:`UnknownDigestError` when the algorithm is unsupported or the
    encoded value cannot be decoded.
    """
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("ascii", "replace")
    text = raw.strip()
    if not text:
        return None

    algo_part: str
    enc_part: str
    if ":" in text:
        algo_part, enc_part = text.split(":", 1)
        explicit_hex = enc_part.startswith("hex:")
        if explicit_hex:
            enc_part = enc_part[4:]
    else:
        # Undefined encoding.  Guess from the character set; default to base32
        # (the WARC conventional form).
        algo_part, enc_part, explicit_hex = "", text, False

    algo = _ALGO_ALIASES.get(algo_part.lower().replace("_", "-"))
    if algo is None:
        raise UnknownDigestError(f"unsupported digest algorithm: {algo_part!r}")

    token = enc_part.strip()
    hex_alphabet = set("0123456789abcdefABCDEF")
    expected_size = hashlib.new(algo).digest_size

    def _from_hex(t: str) -> bytes:
        return bytes.fromhex(t)

    try:
        if explicit_hex:
            decoded = _from_hex(token)
        elif (
            _looks_like(token, hex_alphabet)
            and len(token) == 2 * expected_size
        ):
            # Unambiguous hex: for an n-byte hash, base32 is ceil(8n/5)
            # chars (32 for sha1), hex is 2n (40).  Prefer hex whenever the
            # token only contains hex digits *and* has exactly the hex length.
            decoded = _from_hex(token)
        elif _looks_like(token, set(_B32) | set(_B32.lower())):
            candidate = _decode_b32(token)
            if len(candidate) == expected_size:
                decoded = candidate
            elif _looks_like(token, hex_alphabet):
                decoded = _from_hex(token)
            else:
                decoded = candidate
        elif _looks_like(token, hex_alphabet):
            decoded = _from_hex(token)
        else:
            # Last resort: standard Base64.
            decoded = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4))
    except (binascii.Error, ValueError) as exc:
        raise UnknownDigestError(f"undecodable digest value: {text!r}") from exc

    # Sanity: length must agree with the chosen hash.
    if len(decoded) != hashlib.new(algo).digest_size:
        raise UnknownDigestError(
            f"digest length {len(decoded)} does not match algorithm {algo!r}"
        )
    # Canonical spelling is always upper-case base32, regardless of whether
    # the input used hex, so any two encodings of the same digest compare
    # equal.
    value = base64.b32encode(decoded).decode("ascii").rstrip("=")
    return Digest(algo=algo, value=value, raw=text, digest_bytes=decoded)


def normalize_digest(raw: str | bytes | None) -> str | None:
    """Return canonical ``algo:value`` form, or ``None`` if absent.

    Unlike :func:`parse_digest` this returns ``None`` (does not raise) when
    the value cannot be parsed; callers that index arbitrary WARCs usually
    prefer a warning over aborting the ingest.
    """
    if raw is None:
        return None
    try:
        digest = parse_digest(raw)
    except UnknownDigestError:
        return None
    return str(digest) if digest is not None else None


class DigestHasher:
    """Streaming digest calculator fed with arbitrary byte chunks."""

    __slots__ = ("_h", "algo")

    def __init__(self, algo: str = "sha1") -> None:
        name = _ALGO_ALIASES.get(algo.lower(), algo.lower())
        try:
            self._h = hashlib.new(name)
        except (ValueError, TypeError) as exc:
            raise UnknownDigestError(f"unsupported digest algorithm: {algo!r}") from exc
        self.algo = name

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> Digest:
        raw = self._h.digest()
        value = base64.b32encode(raw).decode("ascii").rstrip("=")
        return Digest(algo=self.algo, value=value,
                      raw=f"{self.algo}:{value}", digest_bytes=raw)

    def hexdigest(self) -> str:
        return self._h.hexdigest()
