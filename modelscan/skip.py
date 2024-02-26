import abc
import logging
from enum import Enum
from pathlib import Path
from typing import Any, List, Union, Dict, Optional

from collections import defaultdict

logger = logging.getLogger("modelscan")


class SkipCategories(Enum):
    SCAN_NOT_SUPPORTED = 1
    BAD_ZIP = 2
    MODEL_CONFIG = 3
    H5_DATA = 4
    NOT_IMPLEMENTED = 5
    MAGIC_NUMBER = 6


class Skip:
    scan_name: str
    category: SkipCategories
    message: str
    source: str

    def __init__(self) -> None:
        pass

    def __str__(self) -> str:
        raise NotImplementedError()


class ModelScanSkipped:
    def __init__(
        self,
        scan_name: str,
        category: SkipCategories,
        message: str,
        source: str,
    ) -> None:
        self.scan_name = scan_name
        self.category = category
        self.message = message
        self.source = str(source)

    def __str__(self) -> str:
        return f"The following file {self.source} was skipped during a {self.scan_name} scan: \n{self.message}"
