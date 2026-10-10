import io
from contextlib import redirect_stdout

from modelscan.modelscan import ModelScan
from modelscan.reports import ConsoleReport


def test_console_report_without_issues_supports_cp1252() -> None:
    raw_output = io.BytesIO()
    output = io.TextIOWrapper(raw_output, encoding="cp1252")

    with redirect_stdout(output):
        ConsoleReport.generate(ModelScan())

    output.flush()
    assert "No issues found!" in raw_output.getvalue().decode("cp1252")
