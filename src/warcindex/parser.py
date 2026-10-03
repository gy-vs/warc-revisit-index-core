"""Incremental WARC/1.0 and WARC/1.1 record parser.

The parser is a push machine: arbitrary-sized byte chunks are handed to
:meth:`WarcStreamParser.feed` (and one final :meth:`feed_eof`); each call
returns the events produced.  Payload chunks are forwarded as they arrive and
never buffered beyond the currently fed chunk, so memory use is independent of
record or file size.

Events: :class:`RecordBegin` -> :class:`PayloadData` (zero or more) ->
:class:`RecordEnd`.
"""

from __future__ import annotations

import re

from .errors import WarcHeaderError, WarcVersionError
from .models import Headers, PayloadData, RecordBegin, RecordEnd
from ._util import (
    SUPPORTED_DIGEST_ALGORITHMS,
    normalize_record_id,
    normalize_uri,
    normalize_warc_date,
    parse_digest,
)

_HEAD = "head"
_BODY = "body"
_GAP = "gap"

_MAX_HEADER_BLOCK = 16 * 1024 * 1024
_VERSION_RE = re.compile(rb"^WARC/1\.[01]$")
_SEPARATORS = (b"\r\n\r\n", b"\r\r", b"\n\n")
_SEPARATOR_PREFIXES = (b"\r", b"\n", b"\r\n", b"\n\r")


class _Current:
    __slots__ = (
        "start",
        "body_start",
        "remaining",
        "truncated",
        "trunc_reason",
        "warnings",
        "bare_lf",
    )

    def __init__(self, start: int, remaining: int, truncated: bool, reason: str | None,
                 warnings: list[str]) -> None:
        self.start = start
        self.body_start: int | None = None
        self.remaining = remaining
        self.truncated = truncated
        self.trunc_reason = reason
        self.warnings = warnings
        self.bare_lf = False


class WarcStreamParser:
    """Parse an arbitrarily chunked WARC byte stream.

    A single instance parses one concatenated stream (one WARC file, or
    several WARC files concatenated).  Not thread-safe.
    """

    def __init__(self) -> None:
        self._buf = b""
        self._offset = 0  # absolute offset of self._buf start in the stream
        self._state = _HEAD
        self._cur: _Current | None = None
        self._last_separator_len = 0
        # head accumulation (only used in HEAD state)
        self._head_raw = bytearray()
        self._head_start = 0
        self._version_seen = False
        self._pending_bare_lf = False
        self._eof = False

    # ------------------------------------------------------------------ API

    def feed(self, data: bytes) -> list:
        if self._eof:
            raise RuntimeError("feed() called after feed_eof()")
        if not data:
            return []
        self._buf += data
        events: list = []
        while self._pump(events):
            pass
        return events

    def feed_eof(self) -> list:
        """Signal end of stream; flush the final record if present."""
        self._eof = True
        events: list = []
        if self._state is _BODY and self._cur is not None:
            # Record block runs to EOF: treat as truncated (no complete
            # Content-Length worth of bytes reached the parser).
            if self._buf:
                events.append(PayloadData(bytes(self._buf)))
                self._offset += len(self._buf)
                self._buf = b""
            self._finish_truncated(events)
            return events
        if self._state is _GAP and self._cur is not None:
            # Missing/incomplete trailing record separator: tolerate, warn.
            self._cur.warnings.append(
                "record at end of stream is not followed by the two-CRLF separator"
            )
            self._buf = b""
            self._emit_end(events)
            return events
        if self._state is _HEAD and (self._version_seen or self._head_raw.strip()):
            raise WarcHeaderError(
                "truncated WARC record header at end of stream", self._head_start
            )
        # leftover blank lines / partial separator bytes are ignored
        self._buf = b""
        return events

    # --------------------------------------------------------------- engine

    def _pump(self, events: list) -> bool:
        if self._state is _HEAD:
            return self._pump_head(events)
        if self._state is _BODY:
            return self._pump_body(events)
        return self._pump_gap(events)

    def _take_line(self) -> bytes | None:
        """Pop one line (without its LF/CRLF ending) from the buffer."""
        idx = self._buf.find(b"\n")
        if idx < 0:
            return None
        line = bytes(self._buf[:idx])
        self._offset += idx + 1
        self._buf = self._buf[idx + 1:]
        if line.endswith(b"\r"):
            line = line[:-1]
        else:
            if self._cur is not None:
                self._cur.bare_lf = True
            elif self._version_seen:
                # header phase before _Cur exists; flag on pending warnings list
                self._pending_bare_lf = True
        return line

    def _line_start(self, line: bytes) -> int:
        """Approximate absolute start of a just-consumed line for errors."""
        return max(0, self._offset - len(line) - 2)

    def _pump_head(self, events: list) -> bool:
        if not self._version_seen and self._cur is None and not self._head_raw:
            self._head_start = self._offset
        while True:
            line = self._take_line()
            if line is None:
                if len(self._head_raw) + len(self._buf) > _MAX_HEADER_BLOCK:
                    raise WarcHeaderError(
                        "WARC header block exceeds maximum size", self._head_start
                    )
                return False
            self._head_raw.extend(line)
            self._head_raw.append(b"\n"[0])

            if not self._version_seen:
                if line.strip() == b"":
                    # blank line between records (or leading blank lines):
                    # restart head accumulation
                    self._head_raw.clear()
                    self._head_start = self._offset
                    continue
                if not _VERSION_RE.match(line.strip()):
                    raise WarcVersionError(
                        f"expected WARC version line, got {line[:40]!r}",
                        self._offset - len(line) - 1,
                    )
                self._version_seen = True
                self._pending_bare_lf = False
                continue

            # version already seen; blank line terminates the header block
            if line.strip() == b"":
                self._begin_record(events)
                # force the outer pump loop to re-examine the new state
                return True

            if len(line) > 0 and b":" not in line:
                raise WarcHeaderError(
                    f"malformed WARC header line (no colon): {line[:60]!r}",
                    self._offset - len(line) - 1,
                )

        return False

    def _begin_record(self, events: list) -> None:
        raw = bytes(self._head_raw)
        warnings: list[str] = []
        if getattr(self, "_pending_bare_lf", False):
            warnings.append("header uses bare LF line endings (RFC requires CRLF)")

        headers = Headers()
        first = True
        for raw_line in raw.split(b"\n"):
            line = raw_line[:-1] if raw_line.endswith(b"\r") else raw_line
            if first:
                first = False
                continue  # version line
            if not line.strip():
                continue
            name, _, value = line.partition(b":")
            headers.add(name.strip(), value.strip())

        rtype_raw = headers.get("WARC-Type")
        if rtype_raw is None:
            raise WarcHeaderError("record missing mandatory WARC-Type", self._head_start)
        rtype = rtype_raw.decode("utf-8", "replace").strip().lower()

        rid_raw = headers.get("WARC-Record-ID")
        if rid_raw is None:
            raise WarcHeaderError(
                "record missing mandatory WARC-Record-ID", self._head_start
            )
        record_id = normalize_record_id(rid_raw.decode("utf-8", "replace"))

        clen_raw = headers.get("Content-Length")
        if clen_raw is None:
            raise WarcHeaderError(
                f"record {record_id} missing mandatory Content-Length",
                self._head_start,
            )
        try:
            clen = int(clen_raw.decode("ascii").strip())
            if clen < 0:
                raise ValueError
        except ValueError:
            raise WarcHeaderError(
                f"record {record_id} has invalid Content-Length: {clen_raw!r}",
                self._head_start,
            )

        truncated = False
        trunc_reason: str | None = None
        tr = headers.get("WARC-Truncated")
        if tr is not None:
            truncated = True
            trunc_reason = tr.decode("utf-8", "replace").strip() or "unspecified"
            warnings.append(f"record is marked truncated: {trunc_reason}")

        date_raw = headers.get("WARC-Date")
        if date_raw is not None:
            normalize_warc_date(date_raw.decode("utf-8", "replace"), warnings)
        elif rtype in ("warcinfo", "response", "revisit", "resource",
                       "metadata", "conversion", "continuation"):
            warnings.append("record is missing WARC-Date")

        digest_raw = headers.get("WARC-Payload-Digest")
        if digest_raw is not None:
            parse_digest(digest_raw.decode("utf-8", "replace"), warnings)
        algo_raw = headers.get("WARC-Payload-Digest-Algorithm")
        if algo_raw is not None and algo_raw.decode("ascii").strip().lower() not in SUPPORTED_DIGEST_ALGORITHMS:
            warnings.append(
                f"unknown WARC-Payload-Digest-Algorithm: {algo_raw!r}"
            )

        uri_raw = headers.get("WARC-Target-URI")
        if uri_raw is not None:
            normalize_uri(uri_raw.decode("utf-8", "replace"))

        self._cur = _Current(
            self._head_start, clen, truncated, trunc_reason, warnings
        )
        self._cur.body_start = self._offset

        self._head_raw.clear()
        self._version_seen = False
        self._pending_bare_lf = False

        events.append(
            RecordBegin(
                offset=self._head_start,
                length=clen,
                record_type=rtype,
                warc_headers=headers,
                raw_header=raw,
                warnings=warnings,
            )
        )

        if clen == 0:
            self._state = _GAP
        else:
            self._state = _BODY

    def _pump_body(self, events: list) -> bool:
        cur = self._cur
        assert cur is not None
        if not self._buf:
            return False
        take = min(len(self._buf), cur.remaining)
        if take:
            events.append(PayloadData(bytes(self._buf[:take])))
            self._buf = self._buf[take:]
            self._offset += take
            cur.remaining -= take
        if cur.remaining == 0:
            self._state = _GAP
            return True
        return False

    def _pump_gap(self, events: list) -> bool:
        cur = self._cur
        assert cur is not None
        if not self._buf:
            return False
        chunk = self._buf[:4]
        for sep in _SEPARATORS:
            if chunk.startswith(sep):
                self._offset += len(sep)
                self._buf = self._buf[len(sep):]
                self._last_separator_len = len(sep)
                self._emit_end(events)
                return True
        # single-byte / two-byte prefixes of a valid separator: need more data
        if any(sep.startswith(bytes(chunk)) for sep in _SEPARATORS):
            return False
        # lenient: bare CRLF only (third/fourth byte missing) handled at EOF;
        # anything else here is garbage between records
        raise WarcFormatError(
            "expected two-CRLF record separator, found "
            f"{bytes(chunk)!r} between records",
            self._offset,
        )

    def _finish_truncated(self, events: list) -> None:
        cur = self._cur
        assert cur is not None
        if not cur.truncated:
            cur.truncated = True
            cur.trunc_reason = cur.trunc_reason or "length"
            cur.warnings.append(
                "record block ends at EOF before declared Content-Length"
            )
        self._emit_end(events)

    def _emit_end(self, events: list) -> None:
        cur = self._cur
        assert cur is not None
        if cur.bare_lf:
            cur.warnings.append("record uses bare LF line endings (RFC requires CRLF)")
        events.append(
            RecordEnd(
                offset=cur.start,
                length=self._offset - cur.start - self._last_separator_len,
                truncated=cur.truncated,
                trunc_reason=cur.trunc_reason,
                warnings=cur.warnings,
            )
        )
        self._cur = None
        self._state = _HEAD
        self._head_raw.clear()
        self._version_seen = False
        self._head_start = self._offset
        self._last_separator_len = 0


def parse_header_block(raw: bytes) -> tuple[str, Headers, list[str]]:
    """Parse a standalone WARC header block (version line + fields + blank).

    Returns ``(record_type, headers, warnings)``.  Used by the record
    materializer which reads a located record directly from disk.
    """
    warnings: list[str] = []
    lines = raw.split(b"\n")
    if not lines:
        raise WarcHeaderError("empty WARC header block")
    version = lines[0][:-1] if lines[0].endswith(b"\r") else lines[0]
    if not _VERSION_RE.match(version.strip()):
        raise WarcVersionError(f"expected WARC version line, got {version[:40]!r}")
    headers = Headers()
    for raw_line in lines[1:]:
        line = raw_line[:-1] if raw_line.endswith(b"\r") else raw_line
        if not line.strip():
            continue
        if b":" not in line:
            raise WarcHeaderError(
                f"malformed WARC header line (no colon): {line[:60]!r}"
            )
        name, _, value = line.partition(b":")
        headers.add(name.strip(), value.strip())
    if headers.get("WARC-Type") is None:
        raise WarcHeaderError("record missing mandatory WARC-Type")
    if headers.get("WARC-Record-ID") is None:
        raise WarcHeaderError("record missing mandatory WARC-Record-ID")
    rtype = headers.get("WARC-Type").decode("utf-8", "replace").strip().lower()
    return rtype, headers, warnings
