"""Internal helpers: field normalization, digest computation, streaming IO."""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

from .errors import WarcHeaderError

SUPPORTED_DIGEST_ALGORITHMS = ("sha1", "sha256", "md5")
DEFAULT_DIGEST_ALGORITHM = "sha1"


# ---------------------------------------------------------------------------
# Date normalization
# ---------------------------------------------------------------------------

def normalize_warc_date(raw: str, warnings: list[str]) -> tuple[str | None, float | None]:
    """Normalize a WARC-Date value.

    Returns ``(canonical, epoch)`` where *canonical* is an ISO-8601 UTC string
    with a ``Z`` suffix (microseconds dropped) and *epoch* is the POSIX
    timestamp.  An unparseable value yields ``(None, None)`` and a warning.
    """
    text = raw.strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        warnings.append(f"unparseable WARC-Date: {raw!r}")
        return None, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return (
        dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        dt.timestamp(),
    )


# ---------------------------------------------------------------------------
# Record-ID / target-URI normalization
# ---------------------------------------------------------------------------

def normalize_record_id(raw: str) -> str:
    """Return the canonical record id.

    Accepts ``<urn:uuid:HEX>``, ``urn:uuid:HEX`` and a bare 32-hex-digit
    UUID.  UUID ids are lower-cased for stable equality; other URNs have only
    surrounding whitespace and angle brackets removed.
    """
    text = raw.strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1].strip()
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        text,
    ):
        text = "urn:uuid:" + text.lower()
    elif text.lower().startswith("urn:uuid:"):
        text = "urn:uuid:" + text[len("urn:uuid:"):].lower()
    return text


def normalize_uri(raw: str) -> str:
    return raw.strip()


# ---------------------------------------------------------------------------
# Digest parsing / computation
# ---------------------------------------------------------------------------

def parse_digest(raw: str, warnings: list[str]) -> tuple[str, str]:
    """Parse a WARC-Payload-Digest value into ``(algorithm, value)``.

    Accepts ``alg:base32``, ``alg:base64`` (with ``=`` padding) and bare
    digests (sha-1 is assumed).  The value is upper-cased per RFC 3548.
    """
    text = raw.strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1].strip()
    if ":" in text:
        algo, _, value = text.partition(":")
        algo = algo.strip().lower()
        value = value.strip().upper()
    else:
        algo = DEFAULT_DIGEST_ALGORITHM
        value = text.upper()
        warnings.append(
            f"digest {raw!r} has no algorithm prefix; assuming {algo}"
        )
    if algo not in SUPPORTED_DIGEST_ALGORITHMS:
        raise WarcHeaderError(f"unsupported digest algorithm in {raw!r}: {algo}")
    if not value:
        raise WarcHeaderError(f"empty digest value in {raw!r}")
    return algo, value


def new_hasher(algorithm: str):
    try:
        return hashlib.new(algorithm)
    except (ValueError, TypeError) as exc:  # pragma: no cover - md5 always present
        raise WarcHeaderError(f"unsupported digest algorithm: {algorithm}") from exc


def hash_bytes(data: bytes, algorithm: str) -> str:
    h = new_hasher(algorithm)
    h.update(data)
    return b32encode(h.digest())


def b32encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii")
