import abc
import logging
from enum import Enum
from pathlib import Path
from typing import Any, List, Union, Dict, Optional

from collections import defaultdict

logger = logging.getLogger("modelscan")


class IssueSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IssueCode(Enum):
    UNSAFE_OPERATOR = 1


class IssueDetails(metaclass=abc.ABCMeta):
    def __init__(self, scanner: str = "") -> None:
        self.scanner = scanner

    @abc.abstractmethod
    def output_lines(self) -> List[str]:
        raise NotImplementedError

    @abc.abstractmethod
    def output_json(self) -> Dict[str, str]:
        raise NotImplementedError


class Issue:
    """
    Defines properties of a issue
    """

    def __init__(
        self,
        code: IssueCode,
        severity: IssueSeverity,
        details: IssueDetails,
    ) -> None:
        """
        Create a issue with given information

        :param code: Code of the issue from the issue code enum.
        :param severity: The severity level of the issue from Severity enum.
        :param details: An implementation of the IssueDetails object.
        """
        self.code = code
        self.severity = severity
        self.details = details

    def __eq__(self, other: Any) -> bool:
        if type(other) is not Issue:
            return False
        return (
            self.code == other.code
            and self.severity == other.severity
            and self.details.module == other.details.module  # type: ignore[attr-defined]
            and self.details.operator == other.details.operator  # type: ignore[attr-defined]
            and str(self.details.source) == str(other.details.source)  # type: ignore[attr-defined]
        )

    def __repr__(self) -> str:
        return str(self.severity) + str(self.details)

    def __hash__(self) -> int:
        return hash(
            str(self.code)
            + str(self.severity)
            + str(self.details.module)  # type: ignore[attr-defined]
            + str(self.details.operator)  # type: ignore[attr-defined]
            + str(self.details.source)  # type: ignore[attr-defined]
        )

    def print(self) -> None:
        issue_description = self.code.name
        if self.code == IssueCode.UNSAFE_OPERATOR:
            issue_description = "Unsafe operator"
        else:
            logger.error(f"No issue description for issue code ${self.code}")

        print(f"\n{issue_description} found:")
        print(f"  - Severity: {self.severity.name}")
        for output_line in self.details.output_lines():
            print(f"  - {output_line}")


class Issues:
    all_issues: List[Issue]

    def __init__(self, issues: Optional[List[Issue]] = None) -> None:
        self.all_issues = [] if issues is None else issues

    def add_issue(self, issue: Issue) -> None:
        """
        Add a single issue
        """
        self.all_issues.append(issue)

    def add_issues(self, issues: List[Issue]) -> None:
        """
        Add a list of issues
        """
        self.all_issues.extend(issues)

    def group_by_severity(self) -> Dict[str, List[Issue]]:
        """
        Group issues by severity.
        """
        issues: Dict[str, List[Issue]] = defaultdict(list)
        for issue in self.all_issues:
            issues[issue.severity.name].append(issue)
        return issues


class OperatorIssueDetails(IssueDetails):
    def __init__(
        self, module: str, operator: str, source: Union[Path, str], scanner: str = ""
    ) -> None:
        self.module = module
        self.operator = operator
        self.source = source
        self.scanner = scanner

    def output_lines(self) -> List[str]:
        return [
            f"Description: Use of unsafe operator '{self.operator}' from module '{self.module}'",
            f"Source: {str(self.source)}",
        ]

    def output_json(self) -> Dict[str, str]:
        return {
            "description": f"Use of unsafe operator '{self.operator}' from module '{self.module}'",
            "operator": f"{self.operator}",
            "module": f"{self.module}",
            "source": f"{str(self.source)}",
            "scanner": f"{self.scanner}",
        }

    def __repr__(self) -> str:
        return f"<OperatorIssueDetails(module={self.module}, operator={self.operator}, source={str(self.source)})>"
