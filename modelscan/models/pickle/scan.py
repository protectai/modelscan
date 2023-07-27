import logging
from pathlib import Path
from typing import IO, List, Tuple, Union, Optional

from modelscan.error import Error
from modelscan.issues import Issue
from modelscan.models.scan import ScanBase
from modelscan.tools.picklescanner import (
    scan_numpy,
    scan_pickle_bytes,
    scan_pytorch,
)

logger = logging.getLogger("modelscan")


class PyTorchScan(ScanBase):
    @staticmethod
    def scan(
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Tuple[List[Issue], List[Error]]:
        if data:
            return scan_pytorch(data=data, source=source)

        with open(source, "rb") as file_io:
            return scan_pytorch(data=file_io, source=source)

    @staticmethod
    def supported_extensions() -> List[str]:
        return [".bin", ".pt", ".pth", ".ckpt"]

    @staticmethod
    def name() -> str:
        return "pytorch"


class NumpyScan(ScanBase):
    @staticmethod
    def scan(
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Tuple[List[Issue], List[Error]]:
        if data:
            return scan_numpy(data=data, source=source)

        with open(source, "rb") as file_io:
            return scan_numpy(data=file_io, source=source)

    @staticmethod
    def supported_extensions() -> List[str]:
        return [".npy"]

    @staticmethod
    def name() -> str:
        return "numpy"


class PickleScan(ScanBase):
    @staticmethod
    def scan(
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Tuple[List[Issue], List[Error]]:
        if data:
            return scan_pickle_bytes(data=data, source=source)

        with open(source, "rb") as file_io:
            return scan_pickle_bytes(data=file_io, source=source)

    @staticmethod
    def supported_extensions() -> List[str]:
        return [".pkl", ".pickle", ".joblib", ".dat", ".data"]

    @staticmethod
    def name() -> str:
        return "pickle"
