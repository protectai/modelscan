import abc
import logging
import json
from typing import Optional, Dict, Any

from rich import print

from modelscan.modelscan import ModelScan
from modelscan.error import Error
from modelscan.issues import Issues, IssueSeverity

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
        raise NotImplemented


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
            print(f"\nTotal Issues By Severity:\n")
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
                print(f"\nSkipped files list:\n")
                for file_name in scan.skipped:
                    print(str(file_name))


class JSONReport(Report):
    @staticmethod
    def generate(
        scan: ModelScan,
        settings: Dict[str, Any] = {},
    ) -> None:
        report: Dict[str, Any] = scan._generate_results()
        if not settings["show_skipped"]:
            del report["skipped"]

        print(json.dumps(report))

        output = settings["output_file"]
        if output:
            with open(output, "w") as outfile:
                json.dump(report, outfile)
