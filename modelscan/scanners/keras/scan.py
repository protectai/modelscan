import json
import zipfile
import logging
from pathlib import Path
from typing import IO, List, Union, Optional


from modelscan.error import ModelScanError, ErrorCategories
from modelscan.skip import ModelScanSkipped, SkipCategories
from modelscan.scanners.scan import ScanResults
from modelscan.scanners.saved_model.scan import SavedModelLambdaDetectScan
from modelscan.model import Model


logger = logging.getLogger("modelscan")


class KerasLambdaDetectScan(SavedModelLambdaDetectScan):
    def scan(self, model: Model) -> Optional[ScanResults]:
        if "keras" not in model.get_context("formats"):
            return None

        dep_error = self.handle_binary_dependencies()
        if dep_error:
            return ScanResults(
                [],
                [
                    ModelScanError(
                        self.name(),
                        ErrorCategories.DEPENDENCY,
                        f"To use {self.full_name()}, please install modelscan with tensorflow extras. `pip install 'modelscan[ tensorflow ]'` if you are using pip.",
                    )
                ],
                [],
            )

        try:
            with zipfile.ZipFile(model.get_stream(), "r") as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    if file_name == "config.json":
                        with zip.open(file_name, "r") as config_file:
                            model = Model(
                                f"{model.get_source()}:{file_name}", config_file
                            )
                            return self.label_results(
                                self._scan_keras_config_file(model)
                            )
        except zipfile.BadZipFile as e:
            return ScanResults(
                [],
                [],
                [
                    ModelScanSkipped(
                        self.name(),
                        SkipCategories.BAD_ZIP,
                        f"Skipping zip file due to error: {e}",
                        f"{model.get_source()}:{file_name}",
                    )
                ],
            )

        # Added return to pass the failing mypy test: Missing return statement
        return ScanResults(
            [],
            [
                ModelScanError(
                    self.name(),
                    ErrorCategories.MODEL_SCAN,  # Giving a generic error category as this return is added to pass mypy
                    f"Unable to scan .keras file",  # Not sure if this is a representative message for ModelScanError
                    str(model.get_source()),
                )
            ],
            [],
        )

    def _scan_keras_config_file(self, model: Model) -> ScanResults:
        machine_learning_library_name = "Keras"

        # if self._check_json_data(source, config_file):

        try:
            operators_in_model = self._get_keras_operator_names(model)
        except json.JSONDecodeError as e:
            logger.error(
                f"Not a valid JSON data from source: {model.get_source()}, error: {e}"
            )

            return ScanResults(
                [],
                [
                    ModelScanError(
                        self.name(),
                        ErrorCategories.JSON_DECODE,
                        f"Not a valid JSON data",
                        str(model.get_source()),
                    )
                ],
                [],
            )

        if operators_in_model:
            return KerasLambdaDetectScan._check_for_unsafe_tf_keras_operator(
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
                [],
            )

    def _get_keras_operator_names(self, model: Model) -> List[str]:
        model_config_data = json.load(model.get_stream())

        lambda_layers = [
            layer.get("config", {}).get("function", {})
            for layer in model_config_data.get("config", {}).get("layers", {})
            if layer.get("class_name", {}) == "Lambda"
        ]
        if lambda_layers:
            return ["Lambda"] * len(lambda_layers)

        return []

    @staticmethod
    def name() -> str:
        return "keras"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.KerasLambdaDetectScan"
