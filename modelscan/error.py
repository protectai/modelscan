from typing import Optional
from enum import Enum


class ErrorCategories(Enum):
    MODEL_SCAN = 1
    DEPENDENCY = 2
    PATH = 3
    NESTED_ZIP = 4
    PICKLE_GENOPS = 5
    JSON_DECODE = 6


class Error:
    scan_name: str
    category: ErrorCategories
    message: str
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
        message: str,
        source: Optional[str] = None,
    ) -> None:
        self.scan_name = scan_name
        self.category = category
        self.message = message
        self.source = source

    def __str__(self) -> str:
        if self.source:
            return f"The following error was raised during a {self.scan_name} scan of file {self.source}: \n{self.message}"
        else:
            return f"The following error was raised during a {self.scan_name} scan: \n{self.message}"
