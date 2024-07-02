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
from modelscan.settings import SupportedModelFormats

logger = logging.getLogger("modelscan")


class PyTorchUnsafeOpScan(ScanBase):
    def scan(
        self,
        model: Model,
    ) -> Optional[ScanResults]:
        if SupportedModelFormats.PYTORCH.value not in [
            format_property.value for format_property in model.get_context("formats")
        ]:
            return None

        if _is_zipfile(model.get_source(), model.get_stream()):
            return None

        results = scan_pytorch(
            model=model,
            settings=self._settings,
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
        model: Model,
    ) -> Optional[ScanResults]:
        if SupportedModelFormats.NUMPY.value not in [
            format_property.value for format_property in model.get_context("formats")
        ]:
            return None

        results = scan_numpy(
            model=model,
            settings=self._settings,
        )

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
        if SupportedModelFormats.PICKLE.value not in [
            format_property.value for format_property in model.get_context("formats")
        ]:
            return None

        results = scan_pickle_bytes(
            model=model,
            settings=self._settings,
        )

        return self.label_results(results)

    @staticmethod
    def name() -> str:
        return "pickle"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.PickleUnsafeOpScan"
