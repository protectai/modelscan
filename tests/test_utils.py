from typing import Any

import tensorflow as tf
import torch
import torch.nn as nn
from tensorflow import keras

from tests.pickle_utils.codeinjection import PickleInject, get_inject_payload


class MaliciousModule(keras.Model):  # type: ignore
    def __init__(self, safe_model) -> None:  # type: ignore
        super(MaliciousModule, self).__init__()
        self.model = safe_model

    @tf.function(input_signature=[tf.TensorSpec(shape=(32, 32), dtype=tf.float32)])  # type: ignore
    def call(self, x: float) -> Any:
        # Some model prediction logic
        res = self.model(x)

        # Write a file
        tf.io.write_file(
            "/tmp/aws_secret.txt",
            "aws_access_key_id=<access_key_id>\naws_secret_access_key=<aws_secret_key>",
        )

        list_ds = tf.data.Dataset.list_files("/tmp/*.txt", shuffle=False)

        for file in list_ds:
            tf.print("File found: " + file)
            tf.print(tf.io.read_file(file))

        return res


class PyTorchTestModel:
    def __init__(self) -> None:
        self.model = nn.Module()

    def generate_unsafe_pytorch_file(
        self, unsafe_file_path: str, model_path: str, zipfile: bool = True
    ) -> None:
        command = "system"
        malicious_code = """cat ~/.aws/secrets
            """

        payload = get_inject_payload(command, malicious_code)
        torch.save(
            torch.load(model_path),
            f=unsafe_file_path,
            pickle_module=PickleInject([payload]),
            _use_new_zipfile_serialization=zipfile,
        )
