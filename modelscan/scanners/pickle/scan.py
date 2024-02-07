import logging
from pathlib import Path
from typing import IO, Union, Optional

from modelscan.scanners.scan import ScanBase, ScanResults
from modelscan.tools.utils import _is_zipfile
from modelscan.tools.picklescanner import (
    scan_numpy,
    scan_pickle_bytes,
    scan_pytorch,
)

logger = logging.getLogger("modelscan")


class PyTorchUnsafeOpScan(ScanBase):
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        if (
            not Path(source).suffix
            in self._settings["scanners"][PyTorchUnsafeOpScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        if _is_zipfile(source):
            return None

        if data:
            results = scan_pytorch(data=data, source=source, settings=self._settings)

        else:
            with open(source, "rb") as file_io:
                results = scan_pytorch(
                    data=file_io, source=source, settings=self._settings
                )

        return self.label_results(results)

    @staticmethod
    def name() -> str:
        return "pytorch"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.PyTorchUnsafeOpScan"


class NumpyUnsafeOpScan(ScanBase):
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        if (
            not Path(source).suffix
            in self._settings["scanners"][NumpyUnsafeOpScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        if data:
            results = scan_numpy(data=data, source=source, settings=self._settings)

        with open(source, "rb") as file_io:
            results = scan_numpy(data=file_io, source=source, settings=self._settings)

        return self.label_results(results)

    @staticmethod
    def name() -> str:
        return "numpy"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.NumpyUnsafeOpScan"


class PickleUnsafeOpScan(ScanBase):
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        if (
            not Path(source).suffix
            in self._settings["scanners"][PickleUnsafeOpScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        if data:
            results = scan_pickle_bytes(
                data=data, source=source, settings=self._settings
            )

        else:
            with open(source, "rb") as file_io:
                results = scan_pickle_bytes(
                    data=file_io, source=source, settings=self._settings
                )

        return self.label_results(results)

    @staticmethod
    def name() -> str:
        return "pickle"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.PickleUnsafeOpScan"
