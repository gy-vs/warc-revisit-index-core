"""Typed error hierarchy for warcindex.

All errors raised by the package derive from :class:`WarcError`, so callers
can catch the whole family with a single ``except`` while still distinguishing
specific failure modes.
"""

from __future__ import annotations


class WarcError(Exception):
    """Base class for every error raised by warcindex."""


# ---------------------------------------------------------------------------
# Parsing / input errors
# ---------------------------------------------------------------------------

class WarcIOError(WarcError):
    """A WARC source file cannot be opened or read."""


class WarcFormatError(WarcError):
    """The byte stream is not valid WARC.

    ``offset``, when known, is the absolute byte offset in the source stream
    at which the problem was detected.
    """

    def __init__(self, message: str, offset: int | None = None) -> None:
        self.offset = offset
        if offset is not None:
            message = f"{message} (at byte offset {offset})"
        super().__init__(message)


class WarcVersionError(WarcFormatError):
    """A record does not start with a supported ``WARC/`` version line."""


class WarcHeaderError(WarcFormatError):
    """A WARC record has malformed or missing mandatory headers."""


class CompressionUnsupportedError(WarcFormatError):
    """A source stream is gzip compressed.

    This release indexes uncompressed WARC files only. Compressed ``warc.gz``
    files must be decompressed (or transparently gunzipped by the caller)
    before ingestion.
    """


# ---------------------------------------------------------------------------
# Index errors
# ---------------------------------------------------------------------------

class IndexError_(WarcError):
    """Base class for index storage and lookup errors."""


class IndexNotFoundError(IndexError_):
    """No index exists at the given directory."""


class IndexFormatError(IndexError_):
    """The on-disk index is corrupt or from an incompatible version."""


class FileChangedError(IndexError_):
    """A previously indexed file changed on disk (its size no longer matches)."""

    def __init__(self, path: str, old_size: int, new_size: int) -> None:
        self.path = path
        self.old_size = old_size
        self.new_size = new_size
        super().__init__(
            f"WARC file {path!r} changed since it was indexed: "
            f"size was {old_size}, now {new_size}"
        )


class DuplicateRecordIdError(IndexError_):
    """A record with the same ``WARC-Record-ID`` is already in the index."""

    def __init__(self, record_id: str) -> None:
        self.record_id = record_id
        super().__init__(f"duplicate WARC-Record-ID already indexed: {record_id}")


class RecordNotFoundError(IndexError_):
    """No record matches the lookup key (record id or revisit target)."""


# ---------------------------------------------------------------------------
# Payload / revisit resolution errors
# ---------------------------------------------------------------------------

class PayloadError(WarcError):
    """Base class for payload materialization errors."""


class TruncatedRecordError(PayloadError):
    """The record (or a revisit's target record) was truncated.

    ``reason`` carries the ``WARC-Truncated`` value when present, otherwise
    ``"unknown"``.
    """

    def __init__(self, record_id: str | None, reason: str = "unknown") -> None:
        self.record_id = record_id
        self.reason = reason
        target = f" record {record_id}" if record_id else " record"
        super().__init__(f"truncated{target}: {reason}")


class DigestMismatchError(PayloadError):
    """A computed payload digest does not agree with the declared digest."""

    def __init__(
        self,
        record_id: str | None,
        algorithm: str,
        expected: str,
        actual: str,
    ) -> None:
        self.record_id = record_id
        self.algorithm = algorithm
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"payload digest mismatch for {record_id or 'record'}: "
            f"expected {algorithm}:{expected}, computed {algorithm}:{actual}"
        )


class RevisitError(PayloadError):
    """Base class for revisit-resolution failures."""


class RevisitTargetNotFoundError(RevisitError, RecordNotFoundError):
    """The record a revisit points at cannot be found in the index."""

    def __init__(self, revisit_id: str | None, target_id: str | None) -> None:
        self.revisit_id = revisit_id
        self.target_id = target_id
        super().__init__(
            f"revisit {revisit_id or '?'} target record "
            f"{target_id or '(unspecified)'} not found in index"
        )


class RevisitDigestMismatchError(RevisitError, DigestMismatchError):
    """The revisit's declared payload digest differs from its target."""


class RevisitTargetTruncatedError(RevisitError, TruncatedRecordError):
    """The record a revisit points at was truncated and cannot serve a body."""


class UnsupportedRevisitProfileError(RevisitError):
    """The revisit uses a profile this library does not know how to resolve."""

    def __init__(self, profile: str) -> None:
        self.profile = profile
        super().__init__(f"unsupported WARC revisit profile: {profile!r}")
