# scan pb files for both tensorflow and keras

import json
import logging
from pathlib import Path

from typing import IO, List, Set, Union, Optional, Dict, Any

try:
    import tensorflow
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel
    from tensorflow.python.keras.protobuf.saved_metadata_pb2 import SavedMetadata

    tensorflow_installed = True
except ImportError:
    tensorflow_installed = False


from modelscan.error import ModelScanError
from modelscan.issues import Issue, IssueCode, IssueSeverity, OperatorIssueDetails
from modelscan.scanners.scan import ScanBase, ScanResults

logger = logging.getLogger("modelscan")


class SavedModelScan(ScanBase):
    def scan(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Optional[ScanResults]:
        if (
            not Path(source).suffix
            in self._settings["scanners"][self.full_name()]["supported_extensions"]
        ):
            return None

        dep_error = self.handle_binary_dependencies()
        if dep_error:
            return ScanResults([], [dep_error])

        if data:
            results = self._scan(source, data)

        else:
            with open(source, "rb") as file_io:
                results = self._scan(source, data=file_io)

        if results:
            return self.label_results(results)
        else:
            return None

    def _scan(self, source: Union[str, Path], data: IO[bytes]) -> Optional[ScanResults]:
        raise NotImplementedError

    # This function checks for malicious operators in both Keras and Tensorflow
    @staticmethod
    def _check_for_unsafe_tf_keras_operator(
        module_name: str,
        raw_operator: List[str],
        source: Union[str, Path],
        unsafe_operators: Dict[str, Any],
    ) -> ScanResults:
        issues: List[Issue] = []
        all_operators = tensorflow.raw_ops.__dict__.keys()
        all_safe_operators = [
            operator for operator in list(all_operators) if operator[0] != "_"
        ]

        for op in raw_operator:
            if op in unsafe_operators:
                severity = IssueSeverity[unsafe_operators[op]]
            elif op not in all_safe_operators:
                severity = IssueSeverity.MEDIUM
            else:
                continue

            issues.append(
                Issue(
                    code=IssueCode.UNSAFE_OPERATOR,
                    severity=severity,
                    details=OperatorIssueDetails(
                        module=module_name, operator=op, source=source
                    ),
                )
            )
        return ScanResults(issues, [])

    def handle_binary_dependencies(
        self, settings: Optional[Dict[str, Any]] = None
    ) -> Optional[ModelScanError]:
        if not tensorflow_installed:
            return ModelScanError(
                self.name(),
                f"To use {self.full_name()}, please install modelscan with tensorflow extras. 'pip install \"modelscan\[tensorflow]\"' if you are using pip.",
            )
        return None

    @staticmethod
    def name() -> str:
        return "saved_model"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.SavedModelScan"


class SavedModelLambdaDetectScan(SavedModelScan):
    def _scan(self, source: Union[str, Path], data: IO[bytes]) -> Optional[ScanResults]:
        file_name = str(source).split("/")[-1]
        if file_name == "keras_metadata.pb":
            machine_learning_library_name = "Keras"
            operators_in_model = self._get_keras_pb_operator_names(
                data=data, source=source
            )

        else:
            return None

        return SavedModelScan._check_for_unsafe_tf_keras_operator(
            machine_learning_library_name,
            operators_in_model,
            source,
            self._settings["scanners"][self.full_name()]["unsafe_keras_operators"],
        )

    @staticmethod
    def _get_keras_pb_operator_names(
        data: IO[bytes], source: Union[str, Path]
    ) -> List[str]:
        saved_metadata = SavedMetadata()
        saved_metadata.ParseFromString(data.read())

        try:
            lambda_layers = [
                layer.get("config", {}).get("function", {}).get("items", {})
                for layer in [
                    json.loads(node.metadata)
                    for node in saved_metadata.nodes
                    if node.identifier == "_tf_keras_layer"
                ]
                if layer.get("class_name", {}) == "Lambda"
            ]
        except json.JSONDecodeError as e:
            logger.error(f"Not a valid JSON data from source: {source}, error: {e}")
            return []

        if lambda_layers:
            return ["Lambda"] * len(lambda_layers)

        return []

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.SavedModelLambdaDetectScan"


class SavedModelTensorflowOpScan(SavedModelScan):
    def _scan(self, source: Union[str, Path], data: IO[bytes]) -> Optional[ScanResults]:
        file_name = str(source).split("/")[-1]
        if file_name == "keras_metadata.pb":
            return None

        else:
            machine_learning_library_name = "Tensorflow"
            operators_in_model = self._get_tensorflow_operator_names(data=data)

        return SavedModelScan._check_for_unsafe_tf_keras_operator(
            machine_learning_library_name,
            operators_in_model,
            source,
            self._settings["scanners"][self.full_name()]["unsafe_tf_operators"],
        )

    def _get_tensorflow_operator_names(self, data: IO[bytes]) -> List[str]:
        saved_model = SavedModel()
        saved_model.ParseFromString(data.read())

        model_op_names: Set[str] = set()
        # Iterate over every metagraph in case there is more than one
        for meta_graph in saved_model.meta_graphs:
            # Add operations in the graph definition
            model_op_names.update(node.op for node in meta_graph.graph_def.node)
            # Go through the functions in the graph definition
            for func in meta_graph.graph_def.library.function:
                # Add operations in each function
                model_op_names.update(node.op for node in func.node_def)
        # Sort and convert to list
        return list(sorted(model_op_names))

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.SavedModelTensorflowOpScan"
