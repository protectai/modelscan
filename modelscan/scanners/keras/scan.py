import json
import zipfile
import logging
from pathlib import Path
from typing import IO, List, Union, Optional


from modelscan.error import ModelScanError
from modelscan.scanners.scan import ScanResults
from modelscan.scanners.saved_model.scan import SavedModelLambdaDetectScan


logger = logging.getLogger("modelscan")


class KerasLambdaDetectScan(SavedModelLambdaDetectScan):
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        if (
            not Path(source).suffix
            in self._settings["scanners"][KerasLambdaDetectScan.full_name()][
                "supported_extensions"
            ]
        ):
            return None

        dep_error = self.handle_binary_dependencies()
        if dep_error:
            return ScanResults([], [dep_error])

        try:
            with zipfile.ZipFile(data or source, "r") as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    if file_name == "config.json":
                        with zip.open(file_name, "r") as config_file:
                            return self.label_results(
                                self._scan_keras_config_file(
                                    source=f"{source}:{file_name}",
                                    config_file=config_file,
                                )
                            )
        except zipfile.BadZipFile as e:
            return ScanResults(
                [],
                [
                    ModelScanError(
                        KerasLambdaDetectScan.name(),
                        f"Skipping zip file {source}, due to error: {e}",
                    )
                ],
            )

        # Added return to pass the failing mypy test: Missing return statement
        return ScanResults(
            [],
            [
                ModelScanError(
                    KerasLambdaDetectScan.name(),
                    f"Unable to scan .keras file",  # Not sure if this is a representative message for ModelScanError
                )
            ],
        )

    def _scan_keras_config_file(
        self, source: Union[str, Path], config_file: IO[bytes]
    ) -> ScanResults:
        machine_learning_library_name = "Keras"
        operators_in_model = self._get_keras_operator_names(source, config_file)
        return KerasLambdaDetectScan._check_for_unsafe_tf_keras_operator(
            module_name=machine_learning_library_name,
            raw_operator=operators_in_model,
            source=source,
            unsafe_operators=self._settings["scanners"][
                SavedModelLambdaDetectScan.full_name()
            ]["unsafe_keras_operators"],
        )

    def _get_keras_operator_names(
        self, source: Union[str, Path], data: IO[bytes]
    ) -> List[str]:
        try:
            model_config_data = json.load(data)
            lambda_layers = [
                layer.get("config", {}).get("function", {})
                for layer in model_config_data.get("config", {}).get("layers", {})
                if layer.get("class_name", {}) == "Lambda"
            ]

            if lambda_layers:
                return ["Lambda"] * len(lambda_layers)

        except json.JSONDecodeError as e:
            logger.error(f"Not a valid JSON data from source: {source}, error: {e}")
            return []

        return []

    @staticmethod
    def name() -> str:
        return "keras"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.KerasLambdaDetectScan"
