"""Helpers to build well-formed WARC records/bytes for the test-suite."""

from __future__ import annotations

import gzip
from typing import Iterable

from warcarchive.digest import DigestHasher

PROFILE_IDENTICAL = (
    "http://netpreserve.org/warc/1.0/revisit/identical-payload-digest"
)
PROFILE_304 = (
    "http://netpreserve.org/warc/1.0/revisit/server-not-modified"
)


def b32_digest(body: bytes, algo: str = "sha1") -> str:
    h = DigestHasher(algo)
    h.update(body)
    return str(h.digest())


def http_response(body: bytes, status: int = 200, headers: dict | None = None,
                  chunked: bool = False) -> bytes:
    if headers is None:
        headers = {}
    if chunked:
        framed = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        hdrs = {"Content-Type": "text/html", "Transfer-Encoding": "chunked"}
    else:
        framed = body
        hdrs = {"Content-Type": "text/html", "Content-Length": str(len(body))}
    hdrs.update(headers)
    reason = {200: "OK", 304: "Not Modified"}.get(status, "OK")
    lines = [f"HTTP/1.1 {status} {reason}\r\n"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}\r\n")
    lines.append("\r\n")
    return "".join(lines).encode("iso-8859-1") + framed


def warc_record(
    record_type: str,
    block: bytes,
    record_id: str | None = None,
    uri: str | None = None,
    date: str = "2026-01-02T03:04:05Z",
    extra_headers: dict | None = None,
    payload_digest: str | None = None,
    truncated: str | None = None,
    force_content_length: int | None = None,
    omit_content_length: bool = False,
) -> bytes:
    rid = record_id or f"urn:uuid:{abs(hash((record_type, uri, date, len(block)))):032x}"
    headers = [
        ("WARC-Type", record_type),
        ("WARC-Record-ID", f"<{rid}>"),
        ("WARC-Date", date),
    ]
    if uri is not None:
        headers.append(("WARC-Target-URI", uri))
    if payload_digest is not None:
        headers.append(("WARC-Payload-Digest", payload_digest))
    if truncated is not None:
        headers.append(("WARC-Truncated", truncated))
    if extra_headers:
        for k, v in extra_headers.items():
            headers.append((k, v))
    lines = ["WARC/1.0\r\n"]
    for k, v in headers:
        lines.append(f"{k}: {v}\r\n")
    if not omit_content_length:
        cl = force_content_length if force_content_length is not None else len(block)
        lines.append(f"Content-Length: {cl}\r\n")
    lines.append("\r\n")
    return "".join(lines).encode("utf-8") + block + b"\r\n\r\n"


def warcinfo(payload: bytes = b"software: test\r\n",
             record_id: str = "urn:uuid:warcinfo-1") -> bytes:
    return warc_record("warcinfo", payload, record_id=record_id)


def gzip_records(records: Iterable[bytes]) -> bytes:
    """Compress each record as its own gzip member (wget-style WARC.GZ)."""
    out = bytearray()
    for rec in records:
        out += gzip.compress(rec, compresslevel=6, mtime=0)
    return bytes(out)


def feed_in_chunks(feeder, data: bytes, sizes: Iterable[int]):
    """Feed data using varying chunk sizes (incl. size 1)."""
    records = []
    i = 0
    sizes = list(sizes)
    k = 0
    while i < len(data):
        size = sizes[k % len(sizes)]
        k += 1
        records.extend(feeder.feed(data[i : i + size]))
        i += size
    records.extend(feeder.finish())
    return records
