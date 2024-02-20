from typing import Optional
from enum import Enum


class ErrorCategories(Enum):
    MODEL_FILE = 1
    JSON_DATA = 2
    DEPENDENCY = 3


class Error:
    def __init__(self) -> None:
        pass

    def __str__(self) -> str:
        raise NotImplementedError()


class ModelScanError(Error):
    scan_name: str
    message: Optional[str]
    source: Optional[str]

    def __init__(
        self,
        scan_name: str,
        message: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        self.scan_name = scan_name
        self.message = message or "None"
        self.source = str(source)

    def __str__(self) -> str:
        return f"The following error was raised during a {self.scan_name} scan: \n{self.message}"
