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
from modelscan.scanners.saved_model.scan import SavedModelLambdaDetectScan

logger = logging.getLogger("modelscan")


class H5LambdaDetectScan(SavedModelLambdaDetectScan):
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        if (
            not Path(source).suffix
            in self._settings["scanners"][H5LambdaDetectScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        dep_error = self.handle_binary_dependencies()
        if dep_error:
            return ScanResults([], [dep_error])

        if data:
            logger.warning(
                "H5 scanner got data bytes. It only support direct file scanning."
            )
            return None

        results = self._scan_keras_h5_file(source)
        if results:
            return self.label_results(results)
        else:
            return None

    def _scan_keras_h5_file(self, source: Union[str, Path]) -> Optional[ScanResults]:
        machine_learning_library_name = "Keras"
        operators_in_model = self._get_keras_h5_operator_names(source)
        if not operators_in_model:
            return None
        return H5LambdaDetectScan._check_for_unsafe_tf_keras_operator(
            module_name=machine_learning_library_name,
            raw_operator=operators_in_model,
            source=source,
            unsafe_operators=self._settings["scanners"][
                SavedModelLambdaDetectScan.full_name()
            ]["unsafe_keras_operators"],
        )

    def _get_keras_h5_operator_names(
        self, source: Union[str, Path]
    ) -> Optional[List[str]]:
        # Todo: source isn't guaranteed to be a file

        with h5py.File(source, "r") as model_hdf5:
            try:
                if not "model_config" in model_hdf5.attrs.keys():
                    return None
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

    def handle_binary_dependencies(
        self, settings: Optional[Dict[str, Any]] = None
    ) -> Optional[ModelScanError]:
        if not h5py_installed:
            return ModelScanError(
                H5LambdaDetectScan.name(),
                f"To use {H5LambdaDetectScan.full_name()}, please install modelscan with h5py extras. 'pip install \"modelscan\[h5py]\"' if you are using pip.",
            )
        return None

    @staticmethod
    def name() -> str:
        return "hdf5"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.H5LambdaDetectScan"
