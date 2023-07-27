import abc
from pathlib import Path
from typing import List, Tuple, Union, Optional, IO

from modelscan.error import Error
from modelscan.issues import Issue


class ScanBase(metaclass=abc.ABCMeta):
    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def scan(
        source: Union[str, Path], data: Optional[IO[bytes]] = None
    ) -> Tuple[List[Issue], List[Error]]:
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
    def supported_extensions() -> List[str]:
        raise NotImplementedError
