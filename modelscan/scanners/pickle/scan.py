import logging
from typing import Any, Dict, Optional

from modelscan.error import DependencyError
from modelscan.scanners.scan import ScanBase, ScanResults
from modelscan.tools.utils import _is_zipfile
from modelscan.tools.picklescanner import (
    numpy_installed,
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

        dep_error = self.handle_binary_dependencies()
        if dep_error:
            return ScanResults(
                [],
                [
                    DependencyError(
                        self.name(),
                        f"To use {self.full_name()}, please install modelscan with numpy extras. `pip install 'modelscan[ numpy ]'` if you are using pip.",
                        model,
                    )
                ],
                [],
            )

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

    def handle_binary_dependencies(
        self, settings: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        if not numpy_installed:
            return DependencyError.name()
        return None


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
