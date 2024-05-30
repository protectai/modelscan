from modelscan.model import Model
import abc
from pathlib import Path
from typing import Dict


class ErrorBase(metaclass=abc.ABCMeta):
    message: str

    def __init__(self, message: str) -> None:
        self.message = message

    @abc.abstractmethod
    def __str__(self) -> str:
        raise NotImplementedError()

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        raise NotImplementedError

    def to_dict(self) -> Dict[str, str]:
        return {
            "category": self.name(),
            "description": self.message,
        }


class ModelScanError(ErrorBase):
    def __str__(self) -> str:
        return f"The following error was raised: \n{self.message}"

    @staticmethod
    def name() -> str:
        return "MODEL_SCAN"


class ModelScanScannerError(ModelScanError):
    scan_name: str
    model: Model

    def __init__(
        self,
        scan_name: str,
        message: str,
        model: Model,
    ) -> None:
        super().__init__(message)
        self.scan_name = scan_name
        self.model = model

    def __str__(self) -> str:
        return f"The following error was raised during a {self.scan_name} scan: \n{self.message}"

    def to_dict(self) -> Dict[str, str]:
        return {
            "category": self.name(),
            "description": self.message,
            "source": str(self.model.get_source()),
        }


class DependencyError(ModelScanScannerError):
    @staticmethod
    def name() -> str:
        return "DEPENDENCY"


class PathError(ErrorBase):
    path: Path

    def __init__(
        self,
        message: str,
        path: Path,
    ) -> None:
        super().__init__(message)
        self.path = path

    def __str__(self) -> str:
        return f"The following error was raised during scan of file {str(self.path)}: \n{self.message}"

    @staticmethod
    def name() -> str:
        return "PATH"

    def to_dict(self) -> Dict[str, str]:
        return {
            "category": self.name(),
            "description": self.message,
            "source": str(self.path),
        }


class NestedZipError(PathError):
    @staticmethod
    def name() -> str:
        return "NESTED_ZIP"


class PickleGenopsError(ModelScanScannerError):
    @staticmethod
    def name() -> str:
        return "PICKLE_GENOPS"


class JsonDecodeError(ModelScanScannerError):
    @staticmethod
    def name() -> str:
        return "JSON_DECODE"
