import json
import logging
from pathlib import Path
from typing import IO, List, Union, Optional, Dict, Any

try:
    import h5py

    h5py_installed = True
except ImportError:
    h5py_installed = False

from modelscan.error import ModelScanError
from modelscan.scanners.scan import ScanResults
from modelscan.scanners.saved_model.scan import SavedModelScan

logger = logging.getLogger("modelscan")


class H5Scan(SavedModelScan):
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        if (
            not Path(source).suffix
            in self._settings[H5Scan.full_name()]["supported_extensions"]
        ):
            return None

        if data:
            logger.warning(
                "H5 scanner got data bytes. It only support direct file scanning."
            )
            return None

        return self.label_results(self._scan_keras_h5_file(source))

    def _scan_keras_h5_file(self, source: Union[str, Path]) -> ScanResults:
        machine_learning_library_name = "Keras"
        operators_in_model = self._get_keras_h5_operator_names(source)
        return H5Scan._check_for_unsafe_tf_keras_operator(
            module_name=machine_learning_library_name,
            raw_operator=operators_in_model,
            source=source,
            settings=self._settings,
        )

    def _get_keras_h5_operator_names(self, source: Union[str, Path]) -> List[str]:
        # Todo: source isn't guaranteed to be a file

        with h5py.File(source, "r") as model_hdf5:
            try:
                model_config = json.loads(model_hdf5.attrs.get("model_config", {}))
                layers = model_config.get("config", {}).get("layers", {})
                lambda_layers = []
                for layer in layers:
                    if layer.get("class_name", {}) == "Lambda":
                        lambda_layers.append(
                            layer.get("config", {}).get("function", {})
                        )
            except json.JSONDecodeError as e:
                logger.error(f"Not a valid JSON data from source: {source}, error: {e}")
                return []

        if lambda_layers:
            return ["Lambda"] * len(lambda_layers)

        return []

    @staticmethod
    def name() -> str:
        return "hdf5"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.H5Scan"

    @staticmethod
    def handle_binary_dependencies(
        settings: Optional[Dict[str, Any]] = None
    ) -> Optional[ModelScanError]:
        if not h5py_installed:
            return ModelScanError(
                SavedModelScan.name(),
                f"To use {H5Scan.full_name()}, please install modelscan with h5py extras. 'pip install \"modelscan\[h5py]\"' if you are using pip.",
            )
        return None
