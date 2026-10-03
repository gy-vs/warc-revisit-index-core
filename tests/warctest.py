"""Helpers for building WARC byte streams in tests."""

from __future__ import annotations

import hashlib
import base64


def b32_digest(data: bytes, algo: str = "sha1") -> str:
    return base64.b32encode(hashlib.new(algo, data).digest()).decode("ascii")


def warc_record(
    *,
    record_type: str,
    record_id: str,
    target_uri: str | None = None,
    date: str = "2026-01-02T03:04:05Z",
    content_type: str | None = None,
    payload_digest: str | None = None,
    refers_to: str | None = None,
    profile: str | None = None,
    truncated: str | None = None,
    block: bytes = b"",
    extra_headers: dict[str, str] | None = None,
    bare_lf: bool = False,
    no_separator: bool = False,
) -> bytes:
    """Serialize one WARC record (CRLF by default)."""
    lines = ["WARC/1.0"]
    lines.append(f"WARC-Type: {record_type}")
    rid = record_id.strip()
    if rid.startswith("urn:uuid:"):
        rid_value = rid[len("urn:uuid:"):]
    elif rid.startswith("<") and rid.endswith(">"):
        rid_value = rid[1:-1]
        if rid_value.startswith("urn:uuid:"):
            rid_value = rid_value[len("urn:uuid:"):]
    else:
        rid_value = rid
    lines.append(f"WARC-Record-ID: <urn:uuid:{rid_value}>")
    if target_uri is not None:
        lines.append(f"WARC-Target-URI: {target_uri}")
    lines.append(f"WARC-Date: {date}")
    if content_type is not None:
        lines.append(f"Content-Type: {content_type}")
    if payload_digest is not None:
        lines.append(f"WARC-Payload-Digest: {payload_digest}")
    if refers_to is not None:
        lines.append(f"WARC-Refers-To: <urn:uuid:{refers_to}>")
    if profile is not None:
        lines.append(f"WARC-Profile: {profile}")
    if truncated is not None:
        lines.append(f"WARC-Truncated: {truncated}")
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    lines.append(f"Content-Length: {len(block)}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    out = head.encode("utf-8") + block
    if not no_separator:
        out += b"\r\n\r\n"
    if bare_lf:
        out = out.replace(b"\r\n", b"\n")
    return out


def http_response(
    body: bytes,
    *,
    status: int = 200,
    reason: str = "OK",
    headers: dict[str, str] | None = None,
    chunked: bool = False,
    include_cl: bool = True,
) -> bytes:
    """Build an HTTP response block."""
    lines = [f"HTTP/1.1 {status} {reason}"]
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if headers:
        hdrs.update(headers)
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    if chunked:
        lines.append("Transfer-Encoding: chunked")
        payload = b""
        for i in range(0, len(body), 17):
            part = body[i:i + 17]
            payload += f"{len(part):X}\r\n".encode() + part + b"\r\n"
        payload += b"0\r\n\r\n"
        block = "\r\n".join(lines).encode("iso-8859-1") + b"\r\n\r\n" + payload
        return block
    if include_cl and status not in (204, 304) and status >= 200:
        lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(lines).encode("iso-8859-1") + b"\r\n\r\n" + body


def warp_payload_digest(body: bytes, algo: str = "sha1") -> str:
    return f"{algo}:{b32_digest(body, algo)}"
