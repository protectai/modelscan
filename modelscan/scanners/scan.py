import abc
from pathlib import Path
from typing import List, Union, Optional, IO, Any, Dict

from modelscan.error import Error, ModelScanError
from modelscan.issues import Issue


class ScanResults:
    issues: List[Issue]
    errors: List[Error]

    def __init__(self, issues: List[Issue], errors: List[Error]) -> None:
        self.issues = issues
        self.errors = errors


class ScanBase(metaclass=abc.ABCMeta):
    def __init__(
        self,
        settings: Dict[str, Any],
    ) -> None:
        self._settings: Dict[str, Any] = settings

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def full_name() -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        raise NotImplementedError

    def handle_binary_dependencies(
        self, settings: Optional[Dict[str, Any]] = None
    ) -> Optional[ModelScanError]:
        """
        Implement this method if the plugin requires a binary dependency.
        It should perform the following actions:

        1. Check if the dependency is installed
        2. Return a ModelScanError prompting the install if not
        """
        return None

    def label_results(self, results: ScanResults) -> ScanResults:
        for issue in results.issues:
            issue.details.scanner = self.full_name()
        return results
