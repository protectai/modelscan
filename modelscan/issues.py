import abc
import logging
from enum import Enum
from pathlib import Path
from typing import Any, List, Union, Dict, Optional

from collections import defaultdict

from modelscan.settings import Property

logger = logging.getLogger("modelscan")


class IssueSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IssueCode:
    UNSAFE_OPERATOR      = Property("UNSAFE_OPERATOR", 1)
    FORMAT_MISMATCH      = Property("FORMAT_MISMATCH", 2)
    INVALID_HEADER       = Property("INVALID_HEADER", 3)
    JSON_PARSING_FAILED  = Property("JSON_PARSING_FAILED", 4)
    SUSPICIOUS_PATTERN   = Property("SUSPICIOUS_PATTERN", 5)
    INVALID_ENCODING     = Property("INVALID_ENCODING", 6)


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
    Defines properties of an issue
    """

    def __init__(
        self,
        code: Property,
        severity: IssueSeverity,
        details: IssueDetails,
    ) -> None:
        """
        Create a issue with given information

        :param code: Code of the issue from the issue code class.
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
            and self.details.severity == other.severity  # type: ignore[attr-defined]
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
            + str(self.details.severity)  # type: ignore[attr-defined]
        )

    def print(self) -> None:
        issue_description = self.code.name
        if self.code.value == IssueCode.UNSAFE_OPERATOR.value:
            issue_description = "Unsafe operator"
        elif self.code.value == IssueCode.FORMAT_MISMATCH.value:
            issue_description = "Format mismatch"
        elif self.code.value == IssueCode.INVALID_HEADER.value:
            issue_description = "Invalid header"
        elif self.code.value == IssueCode.JSON_PARSING_FAILED.value:
            issue_description = "JSON parsing failed"
        elif self.code.value == IssueCode.SUSPICIOUS_PATTERN.value:
            issue_description = "Suspicious pattern"
        elif self.code.value == IssueCode.INVALID_ENCODING.value:
            issue_description = "Invalid encoding"
        else:
            logger.error("No issue description for issue code %s", self.code)

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
        self,
        module: str,
        operator: str,
        severity: IssueSeverity,
        source: Union[Path, str],
        scanner: str = "",
    ) -> None:
        super().__init__(scanner)
        self.module = module
        self.operator = operator
        self.source = source
        self.severity = severity
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
            "severity": f"{self.severity.name}",
        }

    def __repr__(self) -> str:
        return f"<OperatorIssueDetails(module={self.module}, operator={self.operator}, severity={self.severity.name}, source={str(self.source)})>"

class FormatIssueDetails(IssueDetails):
    def __init__(
        self,
        module: str,
        detected_format: str,
        severity: IssueSeverity,
        source: Union[Path, str],
        scanner: str = "",
    ) -> None:
        super().__init__(scanner)
        self.module = module
        self.detected_format = detected_format
        self.source = source
        self.severity = severity
        self.scanner = scanner

    def output_lines(self) -> List[str]:
        return [
            f"Description: Format mismatch detected. Expected 'safetensor' but found '{self.detected_format}'.",
            f"Source: {str(self.source)}",
        ]

    def output_json(self) -> Dict[str, str]:
        return {
            "description": f"Format mismatch detected. Expected 'safetensor' but found '{self.detected_format}'.",
            "detected_format": self.detected_format,
            "module": self.module,
            "source": str(self.source),
            "scanner": self.scanner,
            "severity": self.severity.name,
        }

    def __repr__(self) -> str:
        return (f"<FormatIssueDetails(module={self.module}, detected_format={self.detected_format}, "
                f"severity={self.severity.name}, source={str(self.source)})>")


class JSONParsingIssueDetails(IssueDetails):
    def __init__(
        self,
        error: str,
        source: Union[Path, str],
        severity: IssueSeverity,
        scanner: str = "",
    ) -> None:
        super().__init__(scanner)
        self.error = error
        self.source = source
        self.severity = severity
        self.scanner = scanner

    def output_lines(self) -> List[str]:
        return [
            f"Description: JSON parsing failed with error: {self.error}",
            f"Source: {str(self.source)}"
        ]

    def output_json(self) -> Dict[str, str]:
        return {
            "description": f"JSON parsing failed with error: {self.error}",
            "source": str(self.source),
            "scanner": self.scanner,
            "severity": self.severity.name,
        }

    def __repr__(self) -> str:
        return (f"<JSONParsingIssueDetails(error={self.error}, "
                f"severity={self.severity.name}, source={str(self.source)})>")


class SuspiciousPatternIssueDetails(IssueDetails):
    def __init__(
        self,
        pattern: str,
        source: Union[Path, str],
        severity: IssueSeverity,
        scanner: str = "",
    ) -> None:
        super().__init__(scanner)
        self.pattern = pattern
        self.source = source
        self.severity = severity
        self.scanner = scanner

    def output_lines(self) -> List[str]:
        return [
            f"Description: Suspicious pattern '{self.pattern}' detected in file.",
            f"Source: {str(self.source)}"
        ]

    def output_json(self) -> Dict[str, str]:
        return {
            "description": f"Suspicious pattern '{self.pattern}' detected in file.",
            "pattern": self.pattern,
            "source": str(self.source),
            "scanner": self.scanner,
            "severity": self.severity.name,
        }

    def __repr__(self) -> str:
        return (f"<SuspiciousPatternIssueDetails(pattern={self.pattern}, "
                f"severity={self.severity.name}, source={str(self.source)})>")


class InvalidEncodingIssueDetails(IssueDetails):
    def __init__(
        self,
        source: Union[Path, str],
        error: str,
        severity: IssueSeverity,
        scanner: str = "",
    ) -> None:
        super().__init__(scanner)
        self.source = source
        self.error = error
        self.severity = severity
        self.scanner = scanner

    def output_lines(self) -> List[str]:
        return [
            f"Description: File encoding is invalid: {self.error}",
            f"Source: {str(self.source)}"
        ]

    def output_json(self) -> Dict[str, str]:
        return {
            "description": f"File encoding is invalid: {self.error}",
            "source": str(self.source),
            "scanner": self.scanner,
            "severity": self.severity.name,
        }

    def __repr__(self) -> str:
        return (f"<InvalidEncodingIssueDetails(error={self.error}, "
                f"severity={self.severity.name}, source={str(self.source)})>")
