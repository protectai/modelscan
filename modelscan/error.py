from typing import Optional
from enum import Enum


class ErrorCategories(Enum):
    MODEL_SCAN = 1
    DEPENDENCY = 2
    PATH = 3
    NESTED_ZIP = 4
    PICKLE_GENOPS = 5
    MAGIC_NUMBER = 6
    JSON_DECODE = 7


class Error:
    scan_name: str
    category: ErrorCategories
    message: Optional[str]
    source: Optional[str]

    def __init__(self) -> None:
        pass

    def __str__(self) -> str:
        raise NotImplementedError()


class ModelScanError(Error):
    def __init__(
        self,
        scan_name: str,
        category: ErrorCategories,
        message: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        self.scan_name = scan_name
        self.category = category
        self.message = message or "None"
        self.source = str(source)

    def __str__(self) -> str:
        return f"The following error was raised during a {self.scan_name} scan: \n{self.message}"
