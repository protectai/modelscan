import abc
import logging
import json
import sys
from typing import Optional, Dict, Any, List

from rich import print

from modelscan.modelscan import ModelScan
from modelscan.issues import Issue, IssueCode, IssueSeverity

logger = logging.getLogger("modelscan")


class Report(metaclass=abc.ABCMeta):
    """
    Abstract base class for different reporting modules.
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> Optional[str]:
        """
        Generate report for the given codebase.
        Derived classes must provide implementation of this method.

        :param issues: Instance of Issues object

        :param errors: Any errors that occurred during the scan.
        """
        raise NotImplementedError


class ConsoleReport(Report):
    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> None:
        issues_by_severity = scan.issues.group_by_severity()
        print("\n[blue]--- Summary ---")
        total_issue_count = len(scan.issues.all_issues)
        if total_issue_count > 0:
            print(f"\nTotal Issues: {total_issue_count}")
            print("\nTotal Issues By Severity:\n")
            for severity in IssueSeverity:
                if severity.name in issues_by_severity:
                    print(
                        f"    - {severity.name}: {len(issues_by_severity[severity.name])}"
                    )
                else:
                    print(f"    - {severity.name}: [green]0")

            print("\n[blue]--- Issues by Severity ---")
            for issue_keys in issues_by_severity.keys():
                print(f"\n[blue]--- {issue_keys} ---")
                for issue in issues_by_severity[issue_keys]:
                    issue.print()
        else:
            print("\n[green] No issues found! 🎉")

        if len(scan.errors) > 0:
            print("\n[red]--- Errors --- ")
            for index, error in enumerate(scan.errors):
                print(f"\nError {index+1}:")
                print(str(error))

        if len(scan.skipped) > 0:
            print("\n[blue]--- Skipped --- ")
            print(
                f"\nTotal skipped: {len(scan.skipped)} - run with --show-skipped to see the full list."
            )
            if settings["show_skipped"]:
                print("\nSkipped files list:\n")
                for file_name in scan.skipped:
                    print(str(file_name))


class JSONReport(Report):
    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> None:
        report: Dict[str, Any] = scan._generate_results()
        if not settings.get("show_skipped"):
            del report["summary"]["skipped"]

        print(json.dumps(report))

        output = settings.get("output_file")
        if output:
            with open(output, "w") as outfile:
                json.dump(report, outfile)


class SARIFReport(Report):
    """
    Generate a SARIF v2.1.0 report so scan findings can be consumed by
    GitHub code scanning and any other SARIF-compatible tooling.

    Design notes:
    - ruleId is "<scanner full name>/<issue code>", e.g.
      "modelscan.scanners.PickleUnsafeOpScan/UNSAFE_OPERATOR", so rules from
      different scanners can never collide.
    - Level mapping (chosen to fit GitHub code scanning's error/warning/note
      levels): CRITICAL/HIGH -> error, MEDIUM -> warning, LOW -> note.
    - Model files have no line numbers, so results carry only the file in
      artifactLocation.uri (no region).
    """

    # modelscan IssueSeverity -> SARIF/GitHub code scanning level
    SEVERITY_LEVEL_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }

    @staticmethod
    def _rule_id(issue: Issue) -> str:
        scanner = getattr(issue.details, "scanner", "") or "unknown"
        return f"{scanner}/{issue.code.name}"

    @staticmethod
    def _description(issue: Issue) -> str:
        if issue.code.value == IssueCode.UNSAFE_OPERATOR.value:
            return "Unsafe operator"
        return issue.code.name

    @staticmethod
    def _uri(source: Any) -> str:
        path = str(source)
        if path.startswith("/"):
            return f"file://{path}"
        return path

    @classmethod
    def _build_rule(cls, issue: Issue) -> Dict[str, Any]:
        rule_id = cls._rule_id(issue)
        description = cls._description(issue)
        severity_score = issue.severity.value
        return {
            "id": rule_id,
            "name": issue.code.name,
            "shortDescription": {"text": description},
            "fullDescription": {
                "text": f"{description} (detected by {getattr(issue.details, 'scanner', '') or 'unknown'})"
            },
            "helpUri": "https://protectai.com/docs/modelscan",
            "properties": {
                # CVSS-style score out of 10, derived from the 1-4 severity scale
                "security-severity": str(severity_score * 2.5),
            },
        }

    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> None:
        from modelscan._version import __version__

        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for issue in scan.issues.all_issues:
            rule_id = SARIFReport._rule_id(issue)
            if rule_id not in rules:
                rules[rule_id] = SARIFReport._build_rule(issue)

            results.append(
                {
                    "ruleId": rule_id,
                    "level": SARIFReport.SEVERITY_LEVEL_MAP.get(
                        issue.severity.name, "warning"
                    ),
                    "message": {
                        "text": str(issue.details.output_json().get("description", ""))
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": SARIFReport._uri(
                                        issue.details.source  # type: ignore[attr-defined]
                                    )
                                }
                            }
                        }
                    ],
                }
            )

        report: Dict[str, Any] = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "modelscan",
                            "version": __version__,
                            "informationUri": "https://github.com/protectai/modelscan",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [{"executionSuccessful": True}],
                }
            ],
        }

        # write raw JSON (not rich's print) so rich's soft line-wrapping
        # cannot corrupt the SARIF payload
        sys.stdout.write(json.dumps(report) + "\n")

        output = settings.get("output_file")
        if output:
            with open(output, "w") as outfile:
                json.dump(report, outfile)
