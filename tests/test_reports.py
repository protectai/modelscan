# Tests for the modelscan console report.
from typing import Any, Dict, List

from modelscan.reports import ConsoleReport


class _Issues:
    def __init__(self) -> None:
        self.all_issues: List[Any] = []

    def group_by_severity(self) -> Dict[str, Any]:
        return {}


class _Scan:
    """Minimal stand-in for ModelScan: no issues, no errors, N skipped files."""

    def __init__(self, skipped: List[str]) -> None:
        self.issues = _Issues()
        self.errors: List[Any] = []
        self.skipped = skipped


def test_console_report_does_not_claim_success_when_files_are_skipped(capsys: Any) -> None:
    ConsoleReport.generate(_Scan(["model.bin"]), settings={"show_skipped": False})

    output = capsys.readouterr().out
    assert "No issues found!" not in output
    assert "No issues found in the scanned files" in output
    assert "1 file(s) were skipped" in output


def test_console_report_reports_success_when_nothing_is_skipped(capsys: Any) -> None:
    ConsoleReport.generate(_Scan([]), settings={"show_skipped": False})

    assert "No issues found!" in capsys.readouterr().out
