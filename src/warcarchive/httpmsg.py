"""Minimal HTTP/1.x message parsing and chunked transfer decoding.

Only what a WARC replay index needs: the status code, Content-Length /
Transfer-Encoding and the raw header bytes.  Bodies are decoded lazily by
:class:`Dechunker` so callers never hold a whole payload in memory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .model import HeaderMap, W_BARE_LF, W_HTTP_MALFORMED

_STATUS_LINE = re.compile(rb"^HTTP/\d(?:\.\d)?[ \t]+(\d{3})(?:[ \t]+.*)?$")

# HTTP header blocks we are willing to buffer while scanning for the end.
HTTP_PREFIX_LIMIT = 1 << 20  # 1 MiB


@dataclass(frozen=True, slots=True)
class HttpHead:
    """Parsed HTTP start-line and headers from a WARC response/revisit block."""

    status: int | None
    fields: HeaderMap
    raw: bytes
    bare_lf: bool

    @property
    def content_length(self) -> int | None:
        raw = self.fields.get("Content-Length")
        if raw is None:
            return None
        try:
            return int(raw.strip())
        except ValueError:
            return None

    @property
    def chunked(self) -> bool:
        raw = self.fields.get("Transfer-Encoding")
        return raw is not None and "chunked" in raw.lower()


def find_head_end(data: bytes) -> tuple[int, bool] | None:
    """Find the end of an HTTP header block in ``data``.

    Returns ``(offset after the terminator, bare_lf)`` or ``None`` when the
    block is not complete yet.  CRLF is preferred; a lone-LF blank line is
    accepted but flagged.
    """
    idx = data.find(b"\r\n\r\n")
    if idx != -1:
        return idx + 4, False
    # Tolerant fallback: headers separated/terminated by bare line feeds.
    pos = 0
    while True:
        nl = data.find(b"\n", pos)
        if nl == -1:
            return None
        line_start = pos
        line_end = nl - 1 if data[nl - 1:nl] == b"\r" else nl
        if line_end == line_start:
            # Blank line terminates the block.
            return nl + 1, True
        pos = nl + 1


def parse_http_head(raw: bytes, bare_lf: bool) -> tuple[HttpHead | None, list[str]]:
    """Parse the bytes ending at (and including) the blank separator line."""
    warnings: list[str] = []
    if bare_lf:
        warnings.append(W_BARE_LF)

    text = raw.decode("iso-8859-1")
    lines = text.split("\n")
    if not lines:
        return None, [W_HTTP_MALFORMED]

    start_line = lines[0]
    if start_line.endswith("\r"):
        start_line = start_line[:-1]
    match = _STATUS_LINE.match(start_line.encode("iso-8859-1"))
    if not match:
        warnings.append(W_HTTP_MALFORMED)
        return HttpHead(None, HeaderMap(), raw, bare_lf), warnings
    status = int(match.group(1))

    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines[1:]:
        if line.endswith("\r"):
            line = line[:-1]
        if line == "":
            break
        if ":" not in line:
            warnings.append(W_HTTP_MALFORMED)
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if name == "":
            warnings.append(W_HTTP_MALFORMED)
            continue
        if name.lower() in seen:
            # Keep the first occurrence; duplicates are a smell worth flagging.
            from .model import W_DUPLICATE_HEADER

            warnings.append(W_DUPLICATE_HEADER)
            continue
        seen.add(name.lower())
        pairs.append((name, value))

    return HttpHead(status, HeaderMap(pairs), raw, bare_lf), warnings


class DechunkError(ValueError):
    """The chunked transfer-encoding framing is invalid."""


class Dechunker:
    """Streaming HTTP/1.1 chunked decoder.

    Feed arbitrary byte chunks (including splits at any byte boundary);
    iterate :meth:`feed` output for decoded body chunks.  Call :meth:`eof`
    once the block ends to surface an unterminated framing.
    """

    _SIZE = 0
    _DATA = 1
    _TRAILER = 2
    _DONE = 3
    _MAX_LINE = 65536

    __slots__ = ("_state", "_buf", "_remaining")

    def __init__(self) -> None:
        self._state = self._SIZE
        self._buf = b""
        self._remaining = 0

    def _take_line(self) -> bytes | None:
        nl = self._buf.find(b"\n")
        if nl == -1:
            if len(self._buf) > self._MAX_LINE:
                raise DechunkError("chunk framing line too long")
            return None
        line = self._buf[:nl]
        if line.endswith(b"\r"):
            line = line[:-1]
        self._buf = self._buf[nl + 1:]
        return line

    def feed(self, data: bytes) -> list[bytes]:
        out: list[bytes] = []
        self._buf += data
        while self._buf:
            if self._state == self._SIZE:
                line = self._take_line()
                if line is None:
                    break
                if not line.strip():
                    # Some producers emit an extra blank line before chunks.
                    continue
                size_token = line.split(b";", 1)[0].strip()
                try:
                    size = int(size_token, 16)
                except ValueError:
                    raise DechunkError(f"invalid chunk size: {line!r}") from None
                if size == 0:
                    self._state = self._TRAILER
                    continue
                self._remaining = size
                self._state = self._DATA
            elif self._state == self._DATA:
                if not self._buf:
                    break
                take = min(self._remaining, len(self._buf))
                if take:
                    out.append(self._buf[:take])
                    self._buf = self._buf[take:]
                    self._remaining -= take
                if self._remaining > 0:
                    break
                # Expect CRLF (tolerate bare LF).
                crlf, self._buf = _consume_crlf(self._buf)
                if crlf is None:
                    # Need more bytes to decide; remember that by restoring.
                    # _consume_crlf only returns None when it consumed nothing
                    # ambiguous; loop will break on empty-ish buffer below.
                    break
                self._state = self._SIZE
            elif self._state == self._TRAILER:
                line = self._take_line()
                if line is None:
                    break
                if not line.strip():
                    self._state = self._DONE
                    break
                # trailer line, ignored
            else:  # DONE
                # Anything past the last chunk is a protocol violation, but
                # keep the bytes out of the body.
                self._buf = b""
                break
        return out

    def eof(self) -> None:
        if self._state == self._DONE:
            return
        if self._state == self._TRAILER and self._buf.strip(b"\r\n") == b"":
            # Missing trailers / final blank line at EOF: accept.
            return
        raise DechunkError("chunked payload ended before the final zero-length chunk")


def _consume_crlf(buf: bytes) -> tuple[bool | None, bytes]:
    """Consume a CRLF (or bare LF) trailer after a chunk.

    Returns ``(consumed?, rest)``.  ``None`` means "need more input".
    """
    if buf.startswith(b"\r\n"):
        return True, buf[2:]
    if buf.startswith(b"\n"):
        return True, buf[1:]
    if buf == b"\r":
        return None, buf
    # No trailer where one is required.
    raise DechunkError("missing CRLF after chunk data")
