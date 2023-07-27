# scan pb files for both tensorflow and keras

import json
from pathlib import Path

from typing import IO, List, Set, Tuple, Union, Optional, Dict


try:
    import tensorflow
    from tensorflow.core.protobuf.saved_model_pb2 import SavedModel
    from tensorflow.python.keras.protobuf.saved_metadata_pb2 import SavedMetadata

    tensorflow_installed = True
except ImportError:
    tensorflow_installed = False


from modelscan.error import Error, ModelScanError
from modelscan.issues import Issue, IssueCode, IssueSeverity, OperatorIssueDetails
from modelscan.models.scan import ScanBase


class SavedModelScan(ScanBase):
    @staticmethod
    def scan(
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> Tuple[List[Issue], List[Error]]:
        if not tensorflow_installed:
            return [], [
                ModelScanError(
                    SavedModelScan.name(),
                    f"File: {source} \nTo scan an tensorflow file, please install modelscan with tensorflow extras. 'pip install \"modelscan\[tensorflow]\"' if you are using pip.",
                )
            ]

        if data:
            return SavedModelScan._scan(source, data)

        with open(source, "rb") as file_io:
            return SavedModelScan._scan(source, data=file_io)

    @staticmethod
    def _scan(
        source: Union[str, Path], data: IO[bytes]
    ) -> Tuple[List[Issue], List[Error]]:
        file_name = str(source).split("/")[-1]
        # Default is a tensorflow model file
        if file_name == "keras_metadata.pb":
            machine_learning_library_name = "Keras"
            operators_in_model = SavedModelScan._get_keras_pb_operator_names(data=data)

        else:
            machine_learning_library_name = "Tensorflow"
            operators_in_model = SavedModelScan._get_tensorflow_operator_names(
                data=data
            )

        return SavedModelScan._check_for_unsafe_tf_keras_operator(
            machine_learning_library_name, operators_in_model, source
        )

    @staticmethod
    def _get_keras_pb_operator_names(data: IO[bytes]) -> List[str]:
        saved_metadata = SavedMetadata()
        saved_metadata.ParseFromString(data.read())

        lambda_code = [
            layer.get("config", {}).get("function", {}).get("items", {})
            for layer in [
                json.loads(node.metadata)
                for node in saved_metadata.nodes
                if node.identifier == "_tf_keras_layer"
            ]
            if layer["class_name"] == "Lambda"
        ]

        # if lambda code is not empty list that means there has been some code injection in Keras layer
        if lambda_code:
            keras_operators = ["Lambda"]
        else:
            keras_operators = []

        return keras_operators

    @staticmethod
    def _get_tensorflow_operator_names(data: IO[bytes]) -> List[str]:
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

    # This function checks for malicious operators in both Keras and Tensorflow
    @staticmethod
    def _check_for_unsafe_tf_keras_operator(
        module_name: str, raw_operator: List[str], source: Union[str, Path]
    ) -> Tuple[List[Issue], List[Error]]:
        unsafe_operators: Dict[str, IssueSeverity] = {
            "ReadFile": IssueSeverity.HIGH,
            "WriteFile": IssueSeverity.HIGH,
            "Lambda": IssueSeverity.MEDIUM,
        }
        issues: List[Issue] = []
        all_operators = tensorflow.raw_ops.__dict__.keys()
        all_safe_operators = [
            operator for operator in list(all_operators) if operator[0] != "_"
        ]

        for op in raw_operator:
            if op in unsafe_operators:
                severity = unsafe_operators[op]
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
        return issues, []

    @staticmethod
    def supported_extensions() -> List[str]:
        return [".pb"]

    @staticmethod
    def name() -> str:
        return "saved_model"
