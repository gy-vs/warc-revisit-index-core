import base64

import pytest

from warcarchive.digest import DigestHasher, normalize_digest, parse_digest
from warcarchive.errors import UnknownDigestError


def test_sha1_base32_roundtrip():
    h = DigestHasher("sha1")
    h.update(b"abc")
    digest = h.digest()
    # echo -n abc | sha1sum  -> a9993e364706816aba3e25717850c26c9cd0d89d
    assert digest.hexdigest == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert str(digest) == "sha1:" + base64.b32encode(
        bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
    ).decode().rstrip("=")


def test_parse_warc_style_digests():
    canon = "sha1:" + base64.b32encode(
        bytes.fromhex("a9993e364706816aba3e25717850c26c9cd0d89d")
    ).decode().rstrip("=")
    assert str(parse_digest(canon)) == canon
    # lower-case base32 accepted
    assert str(parse_digest(canon.lower())) == canon
    # hex form is canonicalised to the same base32 spelling
    assert str(parse_digest("sha1:hex:a9993e364706816aba3e25717850c26c9cd0d89d")) \
        == canon
def test_pure_base32_without_algo_raises():
    with pytest.raises(UnknownDigestError):
        parse_digest("Q5MMT4R7AKQ7VUK3")


def test_unknown_algorithm_and_bad_value():
    with pytest.raises(UnknownDigestError):
        parse_digest("crc32:whatever")
    with pytest.raises(UnknownDigestError):
        parse_digest("sha1:not!base32!!")


def test_length_mismatch_rejected():
    # valid base32 but wrong length for sha1
    with pytest.raises(UnknownDigestError):
        parse_digest("sha1:AESUGQ")


def test_none_and_empty():
    assert parse_digest(None) is None
    assert parse_digest("   ") is None
    assert normalize_digest(None) is None
    assert normalize_digest("bogus!!!") is None


def test_matches_is_encoding_insensitive():
    body = b"payload bytes"
    h = DigestHasher("sha1")
    h.update(body)
    d1 = h.digest()
    hex_form = parse_digest("sha1:hex:" + bytes.hex(
        base64.b32decode(d1.value + "=" * ((8 - len(d1.value) % 8) % 8))))
    assert d1.matches(hex_form)
