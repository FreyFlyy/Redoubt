### update_check.py

"""
Optional check of the installed version against the latest GitHub release

Standalone on purpose (stdlib only, no imports from the package): it is the only code that talks
to a host that is not a contact, and it runs only if the user enabled "check version at launch"
"""

import http.client
import json
import re
import urllib.error
import urllib.request


## Variables

REPO = "FreyFlyy/Redoubt"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"   # latest PUBLISHED release (drafts and pre-releases excluded)
RELEASES_URL = f"https://github.com/{REPO}/releases"

TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 1024 * 1024    # a legitimate response is a few KB: refuse anything abnormal

_VERSION_RE = re.compile(r"v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})")


class UpdateCheckError(Exception):
    """The check could not be completed (network error, HTTP error or unexpected data)"""


def parse_version(text) -> tuple:
    """'2.1.1' or 'v2.1.1' -> (2, 1, 1). Anything else (pre-release suffixes included) is rejected, not guessed"""
    if not isinstance(text, str):
        raise UpdateCheckError("Version is not a string")
    match = _VERSION_RE.fullmatch(text.strip())
    if match is None:
        raise UpdateCheckError(f"Unsupported version format: {text[:32]!r}")
    return tuple(int(part) for part in match.groups())


def classify(local: str, remote: str):
    """Compare numerically, not as strings ('2.10.0' > '2.9.0').
    Returns 'update' if remote > local, 'regression' if local > remote, None if equal"""
    local_v, remote_v = parse_version(local), parse_version(remote)
    if remote_v > local_v:
        return "update"
    if local_v > remote_v:
        return "regression"
    return None


def fetch_latest_version(timeout: float = TIMEOUT_SECONDS) -> str:
    """Return the tag of the latest published release without the leading 'v' (e.g. '2.1.1').
    Blocking (up to `timeout` seconds): call it from a worker thread. Raises UpdateCheckError on any failure"""
    request = urllib.request.Request(API_URL, headers={
        "User-Agent": "Redoubt-update-check",   # GitHub requires one. No version/OS: do not leak more than needed
        "Accept": "application/vnd.github+json",
    })

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # TLS certificate verification is on by default
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, ValueError, http.client.HTTPException) as e:   # URLError, HTTPError, SSL errors and timeouts are OSError
        raise UpdateCheckError(f"Request failed: {e}") from e

    if len(raw) > MAX_RESPONSE_BYTES:
        raise UpdateCheckError("Response too large")

    try:
        tag = json.loads(raw)["tag_name"]
    except (ValueError, KeyError, TypeError) as e:
        raise UpdateCheckError("Unexpected response format") from e

    parse_version(tag)  # validates the format
    return tag.strip().lstrip("v")
