import io
import json
import os
import sys

import pytest

from modelscan.modelscan import ModelScan
from modelscan.issues import (
    Issue,
    IssueCode,
    IssueSeverity,
    Issues,
    OperatorIssueDetails,
)
from modelscan.reports import SARIFReport
from modelscan.settings import DEFAULT_SETTINGS

SCHEMA_PATH = os.environ.get(
    "SARIF_SCHEMA_PATH",
    os.path.join(
        os.path.dirname(__file__), "..", "..", "evidence", "sarif-2.1.0-schema.json"
    ),
)


def make_issue(
    severity=IssueSeverity.HIGH,
    scanner="modelscan.scanners.PickleUnsafeOpScan",
    module="builtins",
    operator="eval",
    source="/tmp/model.pkl",
):
    return Issue(
        code=IssueCode.UNSAFE_OPERATOR,
        severity=severity,
        details=OperatorIssueDetails(
            module=module,
            operator=operator,
            severity=severity,
            source=source,
            scanner=scanner,
        ),
    )


def make_scan(issues):
    scan = ModelScan(settings=DEFAULT_SETTINGS)
    scan._issues = Issues(issues)
    return scan


def generate_json(scan, settings=None):
    settings = settings or {}
    captured = io.StringIO()
    old = sys.stdout
    sys.stdout = captured
    try:
        SARIFReport.generate(scan=scan, settings=settings)
    finally:
        sys.stdout = old
    return json.loads(captured.getvalue())


def test_sarif_top_level_structure():
    report = generate_json(make_scan([make_issue()]))
    assert report["version"] == "2.1.0"
    assert report["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(report["runs"]) == 1
    run = report["runs"][0]
    assert run["tool"]["driver"]["name"] == "modelscan"
    assert run["tool"]["driver"]["version"]
    assert len(run["results"]) == 1


def test_severity_level_mapping():
    cases = [
        (IssueSeverity.CRITICAL, "error"),
        (IssueSeverity.HIGH, "error"),
        (IssueSeverity.MEDIUM, "warning"),
        (IssueSeverity.LOW, "note"),
    ]
    for severity, expected_level in cases:
        report = generate_json(make_scan([make_issue(severity=severity)]))
        result = report["runs"][0]["results"][0]
        assert result["level"] == expected_level, f"severity {severity.name}"


def test_rule_id_format_and_dedup():
    issues = [
        make_issue(
            severity=IssueSeverity.HIGH,
            scanner="modelscan.scanners.PickleUnsafeOpScan",
        ),
        make_issue(
            severity=IssueSeverity.CRITICAL,
            scanner="modelscan.scanners.PickleUnsafeOpScan",
        ),
        make_issue(
            severity=IssueSeverity.MEDIUM,
            scanner="modelscan.scanners.H5LambdaDetectScan",
            module="keras",
            operator="Lambda",
            source="/tmp/model.h5",
        ),
    ]
    report = generate_json(make_scan(issues))
    run = report["runs"][0]
    assert len(run["results"]) == 3
    # two issues share scanner+code -> one rule
    assert len(run["tool"]["driver"]["rules"]) == 2
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids == {
        "modelscan.scanners.PickleUnsafeOpScan/UNSAFE_OPERATOR",
        "modelscan.scanners.H5LambdaDetectScan/UNSAFE_OPERATOR",
    }
    for result in run["results"]:
        assert result["ruleId"] in rule_ids


def test_result_message_and_location():
    report = generate_json(make_scan([make_issue(module="builtins", operator="eval")]))
    result = report["runs"][0]["results"][0]
    assert "eval" in result["message"]["text"]
    assert "builtins" in result["message"]["text"]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "file:///tmp/model.pkl"


def test_relative_source_stays_relative():
    report = generate_json(make_scan([make_issue(source="models/model.pkl")]))
    uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "models/model.pkl"


def test_no_issues_empty_results():
    report = generate_json(make_scan([]))
    run = report["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_output_file_written(tmp_path):
    out = tmp_path / "report.sarif"
    generate_json(make_scan([make_issue()]), {"output_file": str(out)})
    assert out.exists()
    report = json.loads(out.read_text())
    assert report["version"] == "2.1.0"
    assert len(report["runs"][0]["results"]) == 1


def test_sarif_schema_valid():
    jsonschema = pytest.importorskip("jsonschema")
    if not os.path.exists(SCHEMA_PATH):
        pytest.skip("SARIF schema not available locally")
    schema = json.loads(open(SCHEMA_PATH).read())
    report = generate_json(
        make_scan(
            [
                make_issue(severity=IssueSeverity.HIGH),
                make_issue(severity=IssueSeverity.MEDIUM),
                make_issue(severity=IssueSeverity.LOW),
            ]
        )
    )
    jsonschema.validate(instance=report, schema=schema)
