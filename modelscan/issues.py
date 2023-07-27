import abc
import logging
from enum import Enum
from pathlib import Path
from typing import List, Union, Dict

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
    @abc.abstractmethod
    def output_lines(self) -> List[str]:
        raise NotImplemented


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
    def __init__(self, issues: List[Issue] = []) -> None:
        self.all_issues: List[Issue] = issues

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
    def __init__(self, module: str, operator: str, source: Union[Path, str]) -> None:
        self.module = module
        self.operator = operator
        self.source = source

    def output_lines(self) -> List[str]:
        return [
            f"Description: Use of unsafe operator '{self.operator}' from module '{self.module}'",
            f"Source: {str(self.source)}",
        ]
