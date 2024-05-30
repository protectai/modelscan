# scan pb files for both tensorflow and keras

import json
import logging

from typing import List, Set, Optional, Dict, Any

try:
    import tensorflow
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel
    from tensorflow.python.keras.protobuf.saved_metadata_pb2 import SavedMetadata

    tensorflow_installed = True
except ImportError:
    tensorflow_installed = False


from modelscan.error import (
    DependencyError,
    JsonDecodeError,
)
from modelscan.issues import Issue, IssueCode, IssueSeverity, OperatorIssueDetails
from modelscan.scanners.scan import ScanBase, ScanResults
from modelscan.model import Model
from modelscan.settings import SupportedModelFormats

logger = logging.getLogger("modelscan")


class SavedModelScan(ScanBase):
    def scan(
        self,
        model: Model,
    ) -> Optional[ScanResults]:
        if SupportedModelFormats.TENSORFLOW.value not in [
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
                        f"To use {self.full_name()}, please install modelscan with tensorflow extras. `pip install 'modelscan[ tensorflow ]'` if you are using pip.",
                        model,
                    )
                ],
                [],
            )

        results = self._scan(model)

        return self.label_results(results) if results else None

    def _scan(self, model: Model) -> Optional[ScanResults]:
        raise NotImplementedError

    # This function checks for malicious operators in both Keras and Tensorflow
    @staticmethod
    def _check_for_unsafe_tf_keras_operator(
        module_name: str,
        raw_operator: List[str],
        model: Model,
        unsafe_operators: Dict[str, Any],
    ) -> ScanResults:
        issues: List[Issue] = []
        all_operators = (
            tensorflow.raw_ops.__dict__.keys() if tensorflow_installed else []
        )
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
                        module=module_name,
                        operator=op,
                        source=str(model.get_source()),
                        severity=severity,
                    ),
                )
            )
        return ScanResults(issues, [], [])

    def handle_binary_dependencies(
        self, settings: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        if not tensorflow_installed:
            return DependencyError.name()
        return None

    @staticmethod
    def name() -> str:
        return "saved_model"

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.SavedModelScan"


class SavedModelLambdaDetectScan(SavedModelScan):
    def _scan(self, model: Model) -> Optional[ScanResults]:
        file_name = str(model.get_source()).split("/")[-1]
        if file_name != "keras_metadata.pb":
            return None

        machine_learning_library_name = "Keras"
        operators_in_model = self._get_keras_pb_operator_names(model)
        if operators_in_model:
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

        return SavedModelScan._check_for_unsafe_tf_keras_operator(
            machine_learning_library_name,
            operators_in_model,
            model,
            self._settings["scanners"][self.full_name()]["unsafe_keras_operators"],
        )

    @staticmethod
    def _get_keras_pb_operator_names(model: Model) -> List[str]:
        saved_metadata = SavedMetadata()
        saved_metadata.ParseFromString(model.get_stream().read())

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
            if lambda_layers:
                return ["Lambda"] * len(lambda_layers)

        except json.JSONDecodeError as e:
            logger.error(
                f"Not a valid JSON data from source: {str(model.get_source())}, error: {e}"
            )
            return ["JSONDecodeError"]

        return []

    @staticmethod
    def full_name() -> str:
        return "modelscan.scanners.SavedModelLambdaDetectScan"


class SavedModelTensorflowOpScan(SavedModelScan):
    def _scan(self, model: Model) -> Optional[ScanResults]:
        file_name = str(model.get_source()).split("/")[-1]
        if file_name == "keras_metadata.pb":
            return None

        machine_learning_library_name = "Tensorflow"
        operators_in_model = self._get_tensorflow_operator_names(model)

        return SavedModelScan._check_for_unsafe_tf_keras_operator(
            machine_learning_library_name,
            operators_in_model,
            model,
            self._settings["scanners"][self.full_name()]["unsafe_tf_operators"],
        )

    def _get_tensorflow_operator_names(self, model: Model) -> List[str]:
        saved_model = SavedModel()
        saved_model.ParseFromString(model.get_stream().read())

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
