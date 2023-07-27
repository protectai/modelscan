import abc
import logging
from typing import List, Optional

from rich import print

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
        issues: Issues,
        errors: List[Error],
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
        issues: Issues,
        errors: List[Error],
    ) -> None:
        issues_by_severity = issues.group_by_severity()
        print("\n[blue]--- Summary ---")
        total_issue_count = len(issues.all_issues)
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

        if len(errors) > 0:
            print("\n[red]--- Errors --- ")
            for index, error in enumerate(errors):
                print(f"\nError {index+1}:")
                print(str(error))
