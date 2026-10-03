"""warcindex — local, disk-backed indexing and replay resolution for WARC files.

Public entry points:

* :func:`iter_records` — read/stream records from a WARC file (the *reading*
  entry point), accepting arbitrarily chunked input under the hood;
* :class:`WarcStreamParser` — low-level push parser for arbitrary byte
  streams;
* :class:`WarcIndex` — build, :meth:`~WarcIndex.save`, reload and query a
  disk-backed index; :meth:`~WarcIndex.resolve` returns the actual HTTP head
  and body (following revisit records);
* :func:`validate_index` — integrity/digest/revisit verification entry point.

All exceptions derive from :class:`errors.WarcError`.
"""

from __future__ import annotations

from .errors import (
    CompressionUnsupportedError,
    DigestMismatchError,
    DuplicateRecordIdError,
    FileChangedError,
    IndexFormatError,
    IndexNotFoundError,
    PayloadError,
    RecordNotFoundError,
    RevisitDigestMismatchError,
    RevisitError,
    RevisitTargetNotFoundError,
    RevisitTargetTruncatedError,
    TruncatedRecordError,
    UnsupportedRevisitProfileError,
    WarcError,
    WarcFormatError,
    WarcHeaderError,
    WarcIOError,
    WarcVersionError,
)
from .index import WarcIndex
from .models import (
    METADATA,
    RawRecordInfo,
    RecordView,
    REVISIT,
    RESPONSE,
    WARCINFO,
)
from .parser import WarcStreamParser
from .reader import ResolvedPayload, iter_records, materialize
from .validation import (
    ValidationIssue,
    ValidationReport,
    validate_index,
)

__version__ = "0.1.0"

__all__ = [
    # entry points
    "iter_records",
    "materialize",
    "WarcStreamParser",
    "WarcIndex",
    "validate_index",
    # result types
    "RawRecordInfo",
    "RecordView",
    "ResolvedPayload",
    "ValidationIssue",
    "ValidationReport",
    # record type constants
    "WARCINFO",
    "RESPONSE",
    "REVISIT",
    "METADATA",
    # error hierarchy
    "WarcError",
    "WarcIOError",
    "WarcFormatError",
    "WarcVersionError",
    "WarcHeaderError",
    "CompressionUnsupportedError",
    "IndexNotFoundError",
    "IndexFormatError",
    "FileChangedError",
    "DuplicateRecordIdError",
    "RecordNotFoundError",
    "PayloadError",
    "TruncatedRecordError",
    "DigestMismatchError",
    "RevisitError",
    "RevisitTargetNotFoundError",
    "RevisitDigestMismatchError",
    "RevisitTargetTruncatedError",
    "UnsupportedRevisitProfileError",
    "__version__",
]
