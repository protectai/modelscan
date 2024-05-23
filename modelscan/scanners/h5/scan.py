import json
import logging
from typing import List, Optional, Dict, Any


try:
    import h5py

    h5py_installed = True
except ImportError:
    h5py_installed = False

from modelscan.error import (
    DependencyError,
    JsonDecodeError,
)
from modelscan.skip import ModelScanSkipped, SkipCategories
from modelscan.scanners.scan import ScanResults
from modelscan.scanners.saved_model.scan import SavedModelLambdaDetectScan
from modelscan.model import Model
from modelscan.settings import SupportedModelFormats

logger = logging.getLogger("modelscan")


class H5LambdaDetectScan(SavedModelLambdaDetectScan):
    def scan(
        self,
        model: Model,
    ) -> Optional[ScanResults]:
        if SupportedModelFormats.KERAS_H5.value not in [
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
                        f"To use {self.full_name()}, please install modelscan with h5py extras. `pip install 'modelscan[ h5py ]'` if you are using pip.",
                        model,
                    )
                ],
                [],
            )

        results = self._scan_keras_h5_file(model)
        if results:
            return self.label_results(results)

        return None

    def _scan_keras_h5_file(self, model: Model) -> Optional[ScanResults]:
        machine_learning_library_name = "Keras"
        if self._check_model_config(model):
            operators_in_model = self._get_keras_h5_operator_names(model)
            if operators_in_model is None:
                return None

            if "JSONDecodeError" in operators_in_model:
                return ScanResults(
                    [],
                    [
                        JsonDecodeError(
                            self.name(),
                            "Not a valid JSON data",
                            model,
                        )
                    ],
                    [],
                )
            return H5LambdaDetectScan._check_for_unsafe_tf_keras_operator(
                module_name=machine_learning_library_name,
                raw_operator=operators_in_model,
                model=model,
                unsafe_operators=self._settings["scanners"][
                    SavedModelLambdaDetectScan.full_name()
                ]["unsafe_keras_operators"],
            )
        else:
            return ScanResults(
                [],
                [],
                [
                    ModelScanSkipped(
                        self.name(),
                        SkipCategories.MODEL_CONFIG,
                        "Model Config not found",
                        str(model.get_source()),
                    )
                ],
            )

    def _check_model_config(self, model: Model) -> bool:
        with h5py.File(model.get_stream()) as model_hdf5:
            if "model_config" in model_hdf5.attrs.keys():
                return True
            else:
                logger.error(f"Model Config not found in: {model.get_source()}")
                return False

    def _get_keras_h5_operator_names(self, model: Model) -> Optional[List[Any]]:
        # Todo: source isn't guaranteed to be a file

        with h5py.File(model.get_stream()) as model_hdf5:
            try:
                if "model_config" not in model_hdf5.attrs.keys():
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
                logger.error(
                    f"Not a valid JSON data from source: {model.get_source()}, error: {e}"
                )
                return ["JSONDecodeError"]

        if lambda_layers:
            return ["Lambda"] * len(lambda_layers)

        return []

    def handle_binary_dependencies(
        self, settings: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        if not h5py_installed:
            return DependencyError.name()
        return None

    @staticmethod
    def name() -> str:
        return "hdf5"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.H5LambdaDetectScan"
