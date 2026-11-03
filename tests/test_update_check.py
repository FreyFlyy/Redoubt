import io
import json
import urllib.error
from unittest import mock

import pytest

from redoubt import update_check as uc


@pytest.mark.parametrize("text,expected", [("2.1.1", (2, 1, 1)), ("v2.10.0", (2, 10, 0)), (" 3.0.0 ", (3, 0, 0))])
def test_parse_version_valid(text, expected):
    assert uc.parse_version(text) == expected


@pytest.mark.parametrize("text", ["", "2.1", "2.1.1.1", "2.1.1-rc1", "latest", "2.1.x", None, 211])
def test_parse_version_invalid(text):
    with pytest.raises(uc.UpdateCheckError):
        uc.parse_version(text)


def test_classify():
    assert uc.classify("2.1.1", "2.2.0") == "update"
    assert uc.classify("2.1.1", "2.1.0") == "regression"
    assert uc.classify("2.1.1", "v2.1.1") is None
    assert uc.classify("2.9.0", "2.10.0") == "update"    # numeric, not lexicographic


def _urlopen_returning(body: bytes):
    return mock.patch("urllib.request.urlopen", return_value=io.BytesIO(body))


def test_fetch_ok_strips_v():
    with _urlopen_returning(json.dumps({"tag_name": "v2.1.1"}).encode()):
        assert uc.fetch_latest_version() == "2.1.1"


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"name": "x"}', b'{"tag_name": "nightly"}', b'{"tag_name": 5}'])
def test_fetch_bad_payload(body):
    with _urlopen_returning(body):
        with pytest.raises(uc.UpdateCheckError):
            uc.fetch_latest_version()


def test_fetch_too_large():
    with _urlopen_returning(b" " * (uc.MAX_RESPONSE_BYTES + 1)):
        with pytest.raises(uc.UpdateCheckError):
            uc.fetch_latest_version()


@pytest.mark.parametrize("exc", [urllib.error.URLError("offline"), TimeoutError(), ConnectionResetError()])
def test_fetch_network_errors(exc):
    with mock.patch("urllib.request.urlopen", side_effect=exc):
        with pytest.raises(uc.UpdateCheckError):
            uc.fetch_latest_version()
