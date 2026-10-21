import json
import pickle
from pathlib import Path

from click.testing import CliRunner

from modelscan.cli import cli
from modelscan.modelscan import ModelScan
from modelscan.reports import JSONReport


def test_scanner_runs_include_clean_issues_errors_and_skips(tmp_path: Path) -> None:
    (tmp_path / "clean.pkl").write_bytes(pickle.dumps({"value": 1}))
    (tmp_path / "unsafe.pkl").write_bytes(b"cos\nsystem\n.")
    (tmp_path / "invalid.pkl").write_bytes(b"\x80")
    (tmp_path / "invalid.pt").write_bytes(b"not a pytorch file")

    scan = ModelScan()
    report = scan.scan(tmp_path)
    runs = {
        entry["source"]: (entry["scanner"], entry["status"])
        for entry in report["summary"]["scanner_runs"]
    }

    assert runs == {
        "clean.pkl": ("modelscan.scanners.PickleUnsafeOpScan", "completed"),
        "unsafe.pkl": ("modelscan.scanners.PickleUnsafeOpScan", "completed"),
        "invalid.pkl": ("modelscan.scanners.PickleUnsafeOpScan", "error"),
        "invalid.pt": ("modelscan.scanners.PyTorchUnsafeOpScan", "skipped"),
    }
    assert report["summary"]["total_issues"] == 1
    assert report["summary"]["scanned"]["total_scanned"] == 2

    output = tmp_path / "report.json"
    JSONReport.generate(scan, {"show_skipped": True, "output_file": str(output)})
    assert (
        json.loads(output.read_text())["summary"]["scanner_runs"]
        == report["summary"]["scanner_runs"]
    )

    second_report = scan.scan(tmp_path / "clean.pkl")
    assert len(second_report["summary"]["scanner_runs"]) == 1
    assert second_report["summary"]["scanner_runs"][0]["source"] == "clean.pkl"


def test_show_scanned_lists_completed_checks(tmp_path: Path) -> None:
    model = tmp_path / "clean.pkl"
    model.write_bytes(pickle.dumps({"value": 1}))

    result = CliRunner().invoke(cli, ["scan", "-p", str(model), "--show-scanned"])

    assert result.exit_code == 0, result.output
    assert "--- Scanner Results ---" in result.output
    assert "modelscan.scanners.PickleUnsafeOpScan (completed)" in result.output
