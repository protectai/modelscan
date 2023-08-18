import json
import zipfile
import logging
from pathlib import Path
from typing import IO, List, Tuple, Union, Optional

from modelscan.error import Error, ModelScanError
from modelscan.issues import Issue
from modelscan.models.saved_model.scan import SavedModelScan

logger = logging.getLogger("modelscan")


class KerasScan(SavedModelScan):
    @staticmethod
    def scan(
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Tuple[List[Issue], List[Error]]:
        try:
            with zipfile.ZipFile(data or source, "r") as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    if file_name == "config.json":
                        with zip.open(file_name, "r") as config_file:
                            return KerasScan._scan_keras_config_file(
                                source=f"{source}:{file_name}", config_file=config_file
                            )
        except zipfile.BadZipFile as e:
            return [], [
                ModelScanError(
                    KerasScan.name(),
                    f"Skipping zip file {source}, due to error: {e}",
                )
            ]

        # Added return to pass the failing mypy test: Missing return statement
        return [], [
            ModelScanError(
                KerasScan.name(),
                f"Unable to scan .keras file",  # Not sure if this is a representative message for ModelScanError
            )
        ]

    @staticmethod
    def _scan_keras_config_file(
        source: Union[str, Path], config_file: IO[bytes]
    ) -> Tuple[List[Issue], List[Error]]:
        machine_learning_library_name = "Keras"
        operators_in_model = KerasScan._get_keras_operator_names(source, config_file)
        return KerasScan._check_for_unsafe_tf_keras_operator(
            module_name=machine_learning_library_name,
            raw_operator=operators_in_model,
            source=source,
        )

    @staticmethod
    def _get_keras_operator_names(
        source: Union[str, Path], data: IO[bytes]
    ) -> List[str]:
        try:
            model_config_data = json.load(data)
            lambda_code = [
                layer.get("config", {}).get("function", {})
                for layer in model_config_data["config"]["layers"]
                if layer["class_name"] == "Lambda"
            ]
        except json.JSONDecodeError as e:
            logger.error(f"Not a valid JSON data from source: {source}, error: {e}")
            return []

        return ["Lambda"] if lambda_code else []

    @staticmethod
    def supported_extensions() -> List[str]:
        return [".keras"]

    @staticmethod
    def name() -> str:
        return ".keras"
