import abc
from typing import List, Optional, Any, Dict

from modelscan.error import ErrorBase
from modelscan.skip import ModelScanSkipped
from modelscan.issues import Issue
from modelscan.model import Model


class ScanResults:
    issues: List[Issue]
    errors: List[ErrorBase]
    skipped: List[ModelScanSkipped]

    def __init__(
        self,
        issues: List[Issue],
        errors: List[ErrorBase],
        skipped: List[ModelScanSkipped],
    ) -> None:
        self.issues = issues
        self.errors = errors
        self.skipped = skipped


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
        model: Model,
    ) -> Optional[ScanResults]:
        raise NotImplementedError

    def handle_binary_dependencies(
        self, settings: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
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
