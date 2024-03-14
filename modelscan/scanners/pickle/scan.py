import logging
from typing import Optional

from modelscan.scanners.scan import ScanBase, ScanResults
from modelscan.tools.utils import _is_zipfile
from modelscan.tools.picklescanner import (
    scan_numpy,
    scan_pickle_bytes,
    scan_pytorch,
)
from modelscan.model import Model

logger = logging.getLogger("modelscan")


class PyTorchUnsafeOpScan(ScanBase):
    def scan(
        self,
        model: Model,
    ) -> Optional[ScanResults]:
        if (
            not model.get_source().suffix
            in self._settings["scanners"][PyTorchUnsafeOpScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        if _is_zipfile(
            model.get_source(), model.get_data() if model.has_data() else None
        ):
            return None

        if model.has_data():
            results = scan_pytorch(
                model=model,
                settings=self._settings,
            )

            return self.label_results(results)

        with open(model.get_source(), "rb") as file_io:
            model = Model(model.get_source(), file_io)
            results = scan_pytorch(model=model, settings=self._settings)

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
        model: Model,
    ) -> Optional[ScanResults]:
        if (
            not model.get_source().suffix
            in self._settings["scanners"][NumpyUnsafeOpScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        if model.has_data():
            results = scan_numpy(
                model=model,
                settings=self._settings,
            )

            return self.label_results(results)

        with open(model.get_source(), "rb") as file_io:
            model = Model(model.get_source(), file_io)
            results = scan_numpy(model=model, settings=self._settings)

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
        model: Model,
    ) -> Optional[ScanResults]:
        if (
            not model.get_source().suffix
            in self._settings["scanners"][PickleUnsafeOpScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        if model.has_data():
            results = scan_pickle_bytes(
                model=model,
                settings=self._settings,
            )

            return self.label_results(results)

        with open(model.get_source(), "rb") as file_io:
            model = Model(model.get_source(), file_io)
            results = scan_pickle_bytes(model=model, settings=self._settings)

        return self.label_results(results)

    @staticmethod
    def name() -> str:
        return "pickle"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.PickleUnsafeOpScan"
