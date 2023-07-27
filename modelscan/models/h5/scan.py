import json
import logging
from pathlib import Path
from typing import IO, List, Tuple, Union, Optional

try:
    import h5py

    h5py_installed = True
except ImportError:
    h5py_installed = False

from modelscan.error import Error, ModelScanError
from modelscan.issues import Issue
from modelscan.models.saved_model.scan import SavedModelScan

logger = logging.getLogger("modelscan")


class H5Scan(SavedModelScan):
    @staticmethod
    def scan(
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Tuple[List[Issue], List[Error]]:
        if not h5py_installed:
            return [], [
                ModelScanError(
                    SavedModelScan.name(),
                    f"File: {source} \nTo scan an h5py file, please install modelscan with h5py extras. 'pip install \"modelscan\[h5py]\"' if you are using pip.",
                )
            ]

        if data:
            logger.warning(
                "H5 scanner got data bytes. It only support direct file scanning."
            )

        return H5Scan._scan_keras_h5_file(source)

    @staticmethod
    def _scan_keras_h5_file(
        source: Union[str, Path]
    ) -> Tuple[List[Issue], List[Error]]:
        machine_learning_library_name = "Keras"
        operators_in_model = H5Scan._get_keras_h5_operator_names(source)
        return H5Scan._check_for_unsafe_tf_keras_operator(
            module_name=machine_learning_library_name,
            raw_operator=operators_in_model,
            source=source,
        )

    @staticmethod
    def _get_keras_h5_operator_names(source: Union[str, Path]) -> List[str]:
        # Todo: source isn't guaranteed to be a file
        with h5py.File(source, "r") as model_hdf5:
            lambda_code = [
                layer.get("config", {}).get("function", {})
                for layer in json.loads(model_hdf5.attrs["model_config"])["config"][
                    "layers"
                ]
                if layer["class_name"] == "Lambda"
            ]

        if lambda_code:
            keras_operator = ["Lambda"]
        else:
            keras_operator = []

        return keras_operator

    @staticmethod
    def supported_extensions() -> List[str]:
        return [".h5"]

    @staticmethod
    def name() -> str:
        return "hdf5"
