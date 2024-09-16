import aiohttp
import bdb
import http.client
import importlib
import io
import numpy as np
import os
from pathlib import Path
import pickle
import dill
import pytest
import requests
import socket
import subprocess
import sys
import torch
import tensorflow as tf
import tf_keras as keras
from typing import Any, List, Set, Dict
from test_utils import (
    generate_dill_unsafe_file,
    generate_unsafe_pickle_file,
    MaliciousModule,
    PyTorchTestModel,
)
import zipfile

from modelscan.modelscan import ModelScan
from modelscan.cli import cli
from modelscan.issues import (
    Issue,
    IssueCode,
    IssueSeverity,
    OperatorIssueDetails,
)
from modelscan.tools.picklescanner import (
    scan_pickle_bytes,
)

from modelscan.skip import SkipCategories
from modelscan.settings import DEFAULT_SETTINGS
from modelscan.model import Model

settings: Dict[str, Any] = DEFAULT_SETTINGS


class Malicious1:
    def __reduce__(self) -> Any:
        return eval, ("print('456')",)


class Malicious2:
    def __reduce__(self) -> Any:
        return os.system, ("ls -la",)


class Malicious3:
    def __reduce__(self) -> Any:
        return http.client.HTTPSConnection, ("github.com",)


malicious3_pickle_bytes = pickle.dumps(
    Malicious3(), protocol=0
)  # Malicious3 needs to be pickled before HTTPSConnection is mocked below


class Malicious4:
    def __reduce__(self) -> Any:
        return requests.get, ("https://github.com",)


class Malicious5:
    def __reduce__(self) -> Any:
        return aiohttp.ClientSession, tuple()


class Malicious6:
    def __reduce__(self) -> Any:
        return socket.create_connection, (("github.com", 80),)


class Malicious7:
    def __reduce__(self) -> Any:
        return subprocess.run, (["ls", "-l"],)


class Malicious8:
    def __reduce__(self) -> Any:
        return sys.exit, (0,)


class Malicious15:
    def __reduce__(self) -> Any:
        bd = bdb.Bdb()
        return bdb.Bdb.run, (
            bd,
            'import os\nos.system("whoami")',
        )


def malicious12_gen() -> bytes:
    p = pickle.PROTO + b"\x05"

    # stack = [pickle.loads]
    p += pickle.GLOBAL + b"pickle\nloads\n"

    # stack = [pickle.loads, p2]
    p2 = (
        pickle.PROTO
        + b"\x05"
        + pickle.GLOBAL
        + b"os\nsystem\n"
        + pickle.UNICODE
        + b"echo pwned!!!\n"
        + pickle.TUPLE1
        + pickle.REDUCE
        + pickle.STOP
    )
    p += pickle.BINBYTES + len(p2).to_bytes(4, "little") + p2

    # stack = [pickle.loads, (p2,)]
    p += pickle.TUPLE1

    # stack = [pickle.loads(p2)]
    p += pickle.REDUCE

    # return None
    p += pickle.POP
    p += pickle.NONE

    p += pickle.STOP
    return p


def malicious13_gen() -> bytes:
    p = pickle.PROTO + b"\x05"

    p += pickle.GLOBAL + b"builtins\neval.__call__\n"
    p += pickle.UNICODE + b'__import__("os").system("echo pwned!!!")\n'
    p += pickle.TUPLE1
    p += pickle.REDUCE

    p += pickle.STOP
    return p


def malicious14_gen() -> bytes:
    p = b"".join(
        [
            pickle.UNICODE + b"os\n",
            pickle.PUT + b"2\n",
            pickle.POP,
            pickle.UNICODE + b"system\n",
            pickle.PUT + b"3\n",
            pickle.POP,
            pickle.UNICODE + b"torch\n",
            pickle.PUT + b"0\n",
            pickle.POP,
            pickle.UNICODE + b"LongStorage\n",
            pickle.PUT + b"1\n",
            pickle.POP,
            pickle.GET + b"2\n",
            pickle.GET + b"3\n",
            pickle.STACK_GLOBAL,
            pickle.MARK,
            pickle.UNICODE + b"cat flag.txt\n",
            pickle.TUPLE,
            pickle.REDUCE,
            pickle.STOP,
            b"\n\n\t\t",
        ]
    )

    return p


def initialize_pickle_file(path: str, obj: Any, version: int) -> None:
    if not os.path.exists(path):
        with open(path, "wb") as file:
            pickle.dump(obj, file, protocol=version)


def initialize_dill_file(path: str, obj: Any, version: int) -> None:
    if not os.path.exists(path):
        with open(path, "wb") as file:
            dill.dump(obj, file, protocol=version)


def initialize_data_file(path: str, data: Any) -> None:
    if not os.path.exists(path):
        with open(path, "wb") as file:
            file.write(data)


def initialize_zip_file(path: str, file_name: str, data: Any) -> None:
    if not os.path.exists(path):
        with zipfile.ZipFile(path, "w") as zip:
            zip.writestr(file_name, data)


@pytest.fixture(scope="session")
def zip_file_path(tmp_path_factory: Any) -> Any:
    tmp = tmp_path_factory.mktemp("zip")
    initialize_zip_file(
        f"{tmp}/test.zip",
        "data.pkl",
        pickle.dumps(Malicious1(), protocol=4),
    )
    return tmp


@pytest.fixture(scope="session")
def pytorch_file_path(tmp_path_factory: Any) -> Any:
    tmp = tmp_path_factory.mktemp("pytorch")
    # Fake PyTorch file (PNG file format) simulating https://huggingface.co/RectalWorm/loras_new/blob/main/Owl_Mage_no_background.pt
    initialize_data_file(f"{tmp}/bad_pytorch.pt", b"\211PNG\r\n\032\n")

    # Safe PyTorch files in old and new (zip) formats
    pt = PyTorchTestModel()
    torch.save(
        pt.model.state_dict(),
        f=f"{tmp}/safe_zip_pytorch.pt",
        _use_new_zipfile_serialization=True,
    )
    torch.save(
        pt.model.state_dict(),
        f=f"{tmp}/safe_old_format_pytorch.pt",
        _use_new_zipfile_serialization=False,
    )

    # Unsafe PyTorch files in new (zip) format
    pt.generate_unsafe_pytorch_file(
        unsafe_file_path=f"{tmp}/unsafe_zip_pytorch.pt",
        model_path=f"{tmp}/safe_zip_pytorch.pt",
        zipfile=True,
    )

    return tmp


@pytest.fixture(scope="session")
def file_path(tmp_path_factory: Any) -> Any:
    tmp = tmp_path_factory.mktemp("test_files")
    os.makedirs(f"{tmp}/data", exist_ok=True)

    # Test with Pickle versions 0, 3, and 4:
    # - Pickle versions 0, 1, 2 have built-in functions under '__builtin__' while versions 3 and 4 have them under 'builtins'
    # - Pickle versions 0, 1, 2, 3 use 'GLOBAL' opcode while 4 uses 'STACK_GLOBAL' opcode
    for version in (0, 3, 4):
        initialize_pickle_file(
            f"{tmp}/data/benign0_v{version}.pkl", ["a", "b", "c"], version
        )
        initialize_pickle_file(
            f"{tmp}/data/malicious1_v{version}.pkl", Malicious1(), version
        )
        initialize_pickle_file(
            f"{tmp}/data/malicious2_v{version}.pkl", Malicious2(), version
        )
        # Dill based files
        initialize_dill_file(
            f"{tmp}/data/benign0_v{version}.dill", ["a", "b", "c"], version
        )
        initialize_dill_file(
            f"{tmp}/data/malicious1_v{version}.dill", Malicious1(), version
        )

    # Malicious Pickle from https://sensepost.com/cms/resources/conferences/2011/sour_pickles/BH_US_11_Slaviero_Sour_Pickles.pdf
    initialize_data_file(
        f"{tmp}/data/malicious0.pkl",
        b'c__builtin__\nglobals\n(tRp100\n0c__builtin__\ncompile\n(S\'fl=open("/etc/passwd");picklesmashed=fl.read();'
        + b"'\nS''\nS'exec'\ntRp101\n0c__builtin__\neval\n(g101\ng100\ntRp102\n0c__builtin__\ngetattr\n(c__builtin__\n"
        + b"dict\nS'get'\ntRp103\n0c__builtin__\napply\n(g103\n(g100\nS'picklesmashed'\nltRp104\n0g104\n.",
    )

    initialize_data_file(f"{tmp}/data/malicious3.pkl", malicious3_pickle_bytes)
    initialize_pickle_file(f"{tmp}/data/malicious4.pickle", Malicious4(), 4)
    initialize_pickle_file(f"{tmp}/data/malicious5.pickle", Malicious5(), 4)
    initialize_data_file(
        f"{tmp}/data/malicious6.pkl",
        pickle.dumps(["a", "b", "c"]) + pickle.dumps(Malicious4()),
    )
    initialize_pickle_file(f"{tmp}/data/malicious7.pkl", Malicious6(), 4)
    initialize_pickle_file(f"{tmp}/data/malicious8.pkl", Malicious7(), 4)
    initialize_pickle_file(f"{tmp}/data/malicious9.pkl", Malicious8(), 4)
    initialize_pickle_file(f"{tmp}/data/malicious15.pkl", Malicious15(), 4)

    # Malicious Pickle from Capture-the-Flag challenge 'Misc/Safe Pickle' at https://imaginaryctf.org/Challenges
    # GitHub Issue: https://github.com/mmaitre314/picklescan/issues/22
    initialize_data_file(
        f"{tmp}/data/malicious11.pkl",
        b"".join(
            [
                pickle.UNICODE + b"os\n",
                pickle.PUT + b"2\n",
                pickle.POP,
                pickle.UNICODE + b"system\n",
                pickle.PUT + b"3\n",
                pickle.POP,
                pickle.UNICODE + b"torch\n",
                pickle.PUT + b"0\n",
                pickle.POP,
                pickle.UNICODE + b"LongStorage\n",
                pickle.PUT + b"1\n",
                pickle.POP,
                pickle.GET + b"2\n",
                pickle.GET + b"3\n",
                pickle.STACK_GLOBAL,
                pickle.MARK,
                pickle.UNICODE + b"cat flag.txt\n",
                pickle.TUPLE,
                pickle.REDUCE,
                pickle.STOP,
            ]
        ),
    )

    initialize_zip_file(
        f"{tmp}/data/malicious1.zip",
        "data.pkl",
        pickle.dumps(Malicious1(), protocol=4),
    )

    malicious10_pickle_bytes = (
        b"(S'print(\"Injection running\")'\ni__builtin__\nexec\n."
    )
    initialize_data_file(f"{tmp}/data/malicious10.pkl", malicious10_pickle_bytes)

    initialize_data_file(f"{tmp}/data/malicious12.pkl", malicious12_gen())

    initialize_data_file(f"{tmp}/data/malicious13.pkl", malicious13_gen())

    initialize_data_file(f"{tmp}/data/malicious14.pkl", malicious14_gen())

    return tmp


@pytest.fixture(scope="session")
def tensorflow_file_path(tmp_path_factory: Any) -> Any:
    # Create a simple model.
    inputs = keras.Input(shape=(32,))
    outputs = keras.layers.Dense(1)(inputs)
    tensorflow_model = keras.Model(inputs, outputs)
    tensorflow_model.compile(optimizer="adam", loss="mean_squared_error")

    # Train a model
    test_input = np.random.random((128, 32))
    test_target = np.random.random((128, 1))
    tensorflow_model.fit(test_input, test_target)

    # Save the safe model
    tmp = tmp_path_factory.mktemp("tensorflow")
    safe_tensorflow_model_dir = tmp / "saved_model_safe"
    safe_tensorflow_model_dir.mkdir(parents=True)
    tensorflow_model.save(safe_tensorflow_model_dir)

    # Create an unsafe model
    unsafe_tensorflow_model = MaliciousModule(tensorflow_model)
    unsafe_tensorflow_model.build(input_shape=(32, 32))

    # Save the unsafe model
    unsafe_tensorflow_model_dir = tmp / "saved_model_unsafe"
    unsafe_tensorflow_model_dir.mkdir(parents=True)
    unsafe_model_path = os.path.join(unsafe_tensorflow_model_dir)
    unsafe_tensorflow_model.save(unsafe_model_path)

    return safe_tensorflow_model_dir, unsafe_tensorflow_model_dir


@pytest.fixture(scope="session")
def keras_file_extensions() -> List[str]:
    return ["h5", "keras", "pb"]


@pytest.fixture(scope="session")
def keras_file_path(tmp_path_factory: Any, keras_file_extensions: List[str]) -> Any:
    # Use Keras 2.0
    os.environ["TF_USE_LEGACY_KERAS"] = "1"

    # Create a simple model.

    inputs = keras.Input(shape=(32,))
    outputs = keras.layers.Dense(1)(inputs)
    keras_model = keras.Model(inputs, outputs)
    keras_model.compile(optimizer="adam", loss="mean_squared_error")

    # Train the model.
    test_input = np.random.random((128, 32))
    test_target = np.random.random((128, 1))
    keras_model.fit(test_input, test_target)

    tmp = tmp_path_factory.mktemp("keras")
    with open(f"{tmp}/safe", "wb") as fo:
        pickle.dump(keras_model, fo)
    for extension in keras_file_extensions:
        if extension == "pb":
            safe_saved_model_dir = tmp / "saved_model_safe"
            safe_saved_model_dir.mkdir(parents=True)
            keras_model.save(f"{safe_saved_model_dir}")
        else:
            keras_model.save(f"{tmp}/safe.{extension}")

    # Inject code with the command
    command = "exec"
    malicious_code = 'print("Malicious code!")'

    generate_dill_unsafe_file(keras_model, command, malicious_code, f"{tmp}/unsafe")
    attack = (
        lambda x: exec(  # type: ignore[func-returns-value]
            """import http.client
import json
import os
conn = http.client.HTTPSConnection("protectai.com")"""
        )
        or x
    )
    input_to_new_layer = keras.layers.Dense(1)(keras_model.layers[-1].output)
    first_lambda_layer = keras.layers.Lambda(attack)(input_to_new_layer)
    second_lambda_layer = keras.layers.Lambda(attack)(first_lambda_layer)

    malicious_model = keras.Model(
        inputs=keras_model.inputs, outputs=[second_lambda_layer]
    )
    malicious_model.compile(optimizer="adam", loss="mean_squared_error")

    for extension in keras_file_extensions:
        if extension == "pb":
            unsafe_saved_model_dir = tmp / "saved_model_unsafe"
            unsafe_saved_model_dir.mkdir(parents=True)
            malicious_model.save(f"{unsafe_saved_model_dir}")
        else:
            malicious_model.save(f"{tmp}/unsafe.{extension}")

    return tmp, safe_saved_model_dir, unsafe_saved_model_dir


@pytest.fixture(scope="session")
def numpy_file_path(tmp_path_factory: Any) -> Any:
    tmp = tmp_path_factory.mktemp("numpy")

    command = "exec"
    malicious_code = 'print("Malicious code!")'
    array_directory = tmp
    if not os.path.isdir(array_directory):
        os.mkdir(array_directory)

    safe_array = [[1, 2, 3], [4, 5, 6]]

    safe_array_path_numpy = os.path.join(array_directory, "safe_numpy.npy")
    np.save(safe_array_path_numpy, safe_array)
    safe_array_numpy = np.load(safe_array_path_numpy, allow_pickle=True)

    unsafe_array_path_numpy = os.path.join(array_directory, "unsafe_numpy.npy")
    generate_unsafe_pickle_file(
        safe_array_numpy, command, malicious_code, unsafe_array_path_numpy
    )

    return tmp


def compare_results(resultList: List[Issue], expectedSet: Set[Issue]) -> None:
    for result in resultList:
        assert result in expectedSet
    resultSet = set(resultList)
    for expected in expectedSet:
        assert expected in resultSet
    assert len(resultList) == len(expectedSet)


def test_scan_pickle_bytes() -> None:
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", IssueSeverity.CRITICAL, "file.pkl"
            ),
        )
    ]

    model = Model("file.pkl", io.BytesIO(pickle.dumps(Malicious1())))
    assert scan_pickle_bytes(model, settings).issues == expected


def test_scan_zip(zip_file_path: Any) -> None:
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{zip_file_path}/test.zip:data.pkl",
            ),
        )
    ]

    ms = ModelScan()
    results = ms.scan(f"{zip_file_path}/test.zip")
    assert results["summary"]["scanned"]["scanned_files"] == ["test.zip:data.pkl"]
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert ms.issues.all_issues == expected


def test_scan_pytorch(pytorch_file_path: Any) -> None:
    ms = ModelScan()
    results = ms.scan(Path(f"{pytorch_file_path}/bad_pytorch.pt"))

    assert results["summary"]["skipped"]["skipped_files"] == [
        {
            "category": SkipCategories.MAGIC_NUMBER.name,
            "description": "Invalid magic number",
            "source": "bad_pytorch.pt",
        }
    ]
    assert ms.issues.all_issues == []

    results = ms.scan(Path(f"{pytorch_file_path}/safe_zip_pytorch.pt"))
    assert results["summary"]["scanned"]["scanned_files"] == [
        "safe_zip_pytorch.pt:safe_zip_pytorch/data.pkl"
    ]

    assert set(
        [
            skipped_file["source"]
            for skipped_file in results["summary"]["skipped"]["skipped_files"]
        ]
    ) == {
        "safe_zip_pytorch.pt:safe_zip_pytorch/byteorder",
        "safe_zip_pytorch.pt:safe_zip_pytorch/version",
        "safe_zip_pytorch.pt:safe_zip_pytorch/.data/serialization_id",
    }
    assert ms.issues.all_issues == []
    assert results["errors"] == []

    results = ms.scan(Path(f"{pytorch_file_path}/safe_old_format_pytorch.pt"))
    assert results["summary"]["scanned"]["scanned_files"] == [
        "safe_old_format_pytorch.pt"
    ]
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert ms.issues.all_issues == []
    assert results["errors"] == []

    unsafe_zip_path = f"{pytorch_file_path}/unsafe_zip_pytorch.pt"
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix",
                "system",
                IssueSeverity.CRITICAL,
                f"{unsafe_zip_path}:unsafe_zip_pytorch/data.pkl",
            ),
        ),
    ]
    results = ms.scan(unsafe_zip_path)
    assert results["summary"]["scanned"]["scanned_files"] == [
        "unsafe_zip_pytorch.pt:unsafe_zip_pytorch/data.pkl",
    ]
    assert set(
        [
            skipped_file["source"]
            for skipped_file in results["summary"]["skipped"]["skipped_files"]
        ]
    ) == {
        "unsafe_zip_pytorch.pt:unsafe_zip_pytorch/byteorder",
        "unsafe_zip_pytorch.pt:unsafe_zip_pytorch/version",
        "unsafe_zip_pytorch.pt:unsafe_zip_pytorch/.data/serialization_id",
    }
    assert ms.issues.all_issues == expected
    assert results["errors"] == []


def test_scan_numpy(numpy_file_path: Any) -> None:
    ms = ModelScan()
    results = ms.scan(f"{numpy_file_path}/safe_numpy.npy")
    assert ms.issues.all_issues == []
    assert results["summary"]["scanned"]["scanned_files"] == ["safe_numpy.npy"]
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert results["errors"] == []

    expected = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "exec",
                IssueSeverity.CRITICAL,
                f"{numpy_file_path}/unsafe_numpy.npy",
            ),
        ),
    }

    results = ms.scan(f"{numpy_file_path}/unsafe_numpy.npy")
    compare_results(ms.issues.all_issues, expected)
    assert results["summary"]["scanned"]["scanned_files"] == ["unsafe_numpy.npy"]
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert results["errors"] == []


def test_scan_file_path(file_path: Any) -> None:
    benign_pickle = ModelScan()
    results = benign_pickle.scan(Path(f"{file_path}/data/benign0_v3.pkl"))
    assert benign_pickle.issues.all_issues == []
    assert results["summary"]["scanned"]["scanned_files"] == ["benign0_v3.pkl"]
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert results["errors"] == []

    benign_dill = ModelScan()
    results = benign_dill.scan(Path(f"{file_path}/data/benign0_v3.dill"))
    assert benign_dill.issues.all_issues == []
    assert results["summary"]["scanned"]["scanned_files"] == ["benign0_v3.dill"]
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert results["errors"] == []

    malicious0 = ModelScan()
    expected_malicious0 = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "apply",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "compile",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "getattr",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
    }
    results = malicious0.scan(Path(f"{file_path}/data/malicious0.pkl"))
    compare_results(malicious0.issues.all_issues, expected_malicious0)
    assert results["summary"]["scanned"]["scanned_files"] == ["malicious0.pkl"]
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert results["errors"] == []


def test_scan_pickle_operators(file_path: Any) -> None:
    # Tests the unsafe pickle operators we screen for, across differences in pickle versions 0-2, 3, and 4
    expected_malicious1_v0 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v0.pkl",
            ),
        )
    ]
    expected_malicious1_v3 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v3.pkl",
            ),
        )
    ]
    expected_malicious1_v4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v4.pkl",
            ),
        )
    ]
    # dill based malicious1
    expected_malicious1_v0_dill = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v0.dill",
            ),
        )
    ]
    expected_malicious1_v3_dill = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v3.dill",
            ),
        )
    ]
    expected_malicious1_v4_dill = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v4.dill",
            ),
        )
    ]

    expected_malicious1 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1.zip:data.pkl",
            ),
        )
    ]
    malicious1_v0 = ModelScan()
    malicious1_v3 = ModelScan()
    malicious1_v4 = ModelScan()
    malicious1_v0_dill = ModelScan()
    malicious1_v3_dill = ModelScan()
    malicious1_v4_dill = ModelScan()

    malicious1 = ModelScan()
    malicious1_v0.scan(Path(f"{file_path}/data/malicious1_v0.pkl"))
    malicious1_v3.scan(Path(f"{file_path}/data/malicious1_v3.pkl"))
    malicious1_v4.scan(Path(f"{file_path}/data/malicious1_v4.pkl"))
    malicious1_v0_dill.scan(Path(f"{file_path}/data/malicious1_v0.dill"))
    malicious1_v3_dill.scan(Path(f"{file_path}/data/malicious1_v3.dill"))
    malicious1_v4_dill.scan(Path(f"{file_path}/data/malicious1_v4.dill"))
    malicious1.scan(Path(f"{file_path}/data/malicious1.zip"))
    assert malicious1_v0.issues.all_issues == expected_malicious1_v0
    assert malicious1_v3.issues.all_issues == expected_malicious1_v3
    assert malicious1_v4.issues.all_issues == expected_malicious1_v4
    assert malicious1_v0_dill.issues.all_issues == expected_malicious1_v0_dill
    assert malicious1_v3_dill.issues.all_issues == expected_malicious1_v3_dill
    assert malicious1_v4_dill.issues.all_issues == expected_malicious1_v4_dill
    assert malicious1.issues.all_issues == expected_malicious1

    expected_malicious2_v0 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious2_v0.pkl",
            ),
        )
    ]
    expected_malicious2_v3 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious2_v3.pkl",
            ),
        )
    ]
    expected_malicious2_v4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious2_v4.pkl",
            ),
        )
    ]
    malicious2_v0 = ModelScan()
    malicious2_v3 = ModelScan()
    malicious2_v4 = ModelScan()
    malicious2_v0.scan(Path(f"{file_path}/data/malicious2_v0.pkl"))
    malicious2_v3.scan(Path(f"{file_path}/data/malicious2_v3.pkl"))
    malicious2_v4.scan(Path(f"{file_path}/data/malicious2_v4.pkl"))
    assert malicious2_v0.issues.all_issues == expected_malicious2_v0
    assert malicious2_v3.issues.all_issues == expected_malicious2_v3
    assert malicious2_v4.issues.all_issues == expected_malicious2_v4

    expected_malicious3 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "httplib",
                "HTTPSConnection",
                IssueSeverity.HIGH,
                Path(f"{file_path}/data/malicious3.pkl"),
            ),
        )
    ]
    malicious3 = ModelScan()
    malicious3.scan(Path(f"{file_path}/data/malicious3.pkl"))
    assert malicious3.issues.all_issues == expected_malicious3

    expected_malicious4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api",
                "get",
                IssueSeverity.HIGH,
                f"{file_path}/data/malicious4.pickle",
            ),
        )
    ]
    malicious4 = ModelScan()
    malicious4.scan(Path(f"{file_path}/data/malicious4.pickle"))
    assert malicious4.issues.all_issues == expected_malicious4

    expected_malicious5 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "aiohttp.client",
                "ClientSession",
                IssueSeverity.HIGH,
                f"{file_path}/data/malicious5.pickle",
            ),
        )
    ]
    malicious5 = ModelScan()
    malicious5.scan(Path(f"{file_path}/data/malicious5.pickle"))
    assert malicious5.issues.all_issues == expected_malicious5

    expected_malicious6 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api",
                "get",
                IssueSeverity.HIGH,
                f"{file_path}/data/malicious6.pkl",
            ),
        )
    ]
    malicious6 = ModelScan()
    malicious6.scan(Path(f"{file_path}/data/malicious6.pkl"))
    assert malicious6.issues.all_issues == expected_malicious6

    expected_malicious7 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "socket",
                "create_connection",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious7.pkl",
            ),
        )
    ]
    malicious7 = ModelScan()
    malicious7.scan(Path(f"{file_path}/data/malicious7.pkl"))
    assert malicious7.issues.all_issues == expected_malicious7

    expected_malicious8 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "subprocess",
                "run",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious8.pkl",
            ),
        )
    ]
    malicious8 = ModelScan()
    malicious8.scan(Path(f"{file_path}/data/malicious8.pkl"))
    assert malicious8.issues.all_issues == expected_malicious8

    expected_malicious9 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "sys",
                "exit",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious9.pkl",
            ),
        )
    ]
    malicious9 = ModelScan()
    malicious9.scan(Path(f"{file_path}/data/malicious9.pkl"))
    assert malicious9.issues.all_issues == expected_malicious9

    expected_malicious10 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "exec",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious10.pkl",
            ),
        )
    ]
    malicious10 = ModelScan()
    malicious10.scan(Path(f"{file_path}/data/malicious10.pkl"))
    assert malicious10.issues.all_issues == expected_malicious10

    expected_malicious11 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "os",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious11.pkl",
            ),
        )
    ]
    malicious11 = ModelScan()
    malicious11.scan(Path(f"{file_path}/data/malicious11.pkl"))
    assert malicious11.issues.all_issues == expected_malicious11
    expected_malicious12 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "pickle",
                "loads",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious12.pkl",
            ),
        )
    ]
    malicious12 = ModelScan()
    malicious12.scan(Path(f"{file_path}/data/malicious12.pkl"))
    assert malicious12.issues.all_issues == expected_malicious12
    expected_malicious13 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval.__call__",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious13.pkl",
            ),
        )
    ]
    malicious13 = ModelScan()
    malicious13.scan(Path(f"{file_path}/data/malicious13.pkl"))
    assert malicious13.issues.all_issues == expected_malicious13

    expected_malicious14 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "os",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious14.pkl",
            ),
        )
    ]
    malicious14 = ModelScan()
    malicious14.scan(Path(f"{file_path}/data/malicious14.pkl"))
    assert malicious14.issues.all_issues == expected_malicious14

    expected_malicious15 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "bdb",
                "Bdb.run",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious15.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "bdb",
                "Bdb",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious15.pkl",
            ),
        ),
    ]
    malicious15 = ModelScan()
    malicious15.scan(Path(f"{file_path}/data/malicious15.pkl"))
    assert sorted(malicious15.issues.all_issues, key=str) == sorted(
        expected_malicious15, key=str
    )


def test_scan_directory_path(file_path: str) -> None:
    expected = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1.zip:data.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "subprocess",
                "run",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious8.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "sys",
                "exit",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious9.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api",
                "get",
                IssueSeverity.HIGH,
                f"{file_path}/data/malicious4.pickle",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v3.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v4.pkl",
            ),
        ),
        # dill based expected issues
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v3.dill",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v0.dill",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious1_v4.dill",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "aiohttp.client",
                "ClientSession",
                IssueSeverity.HIGH,
                f"{file_path}/data/malicious5.pickle",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious2_v4.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "socket",
                "create_connection",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious7.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api",
                "get",
                IssueSeverity.HIGH,
                f"{file_path}/data/malicious6.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "compile",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "eval",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "apply",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "getattr",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious2_v3.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "httplib",
                "HTTPSConnection",
                IssueSeverity.HIGH,
                f"{file_path}/data/malicious3.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious2_v0.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "exec",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious10.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "os",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious11.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "pickle",
                "loads",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious12.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins",
                "eval.__call__",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious13.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "os",
                "system",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious14.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "bdb",
                "Bdb",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious15.pkl",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "bdb",
                "Bdb.run",
                IssueSeverity.CRITICAL,
                f"{file_path}/data/malicious15.pkl",
            ),
        ),
    }
    ms = ModelScan()
    p = Path(f"{file_path}/data/")
    results = ms.scan(p)
    compare_results(ms.issues.all_issues, expected)
    assert set(results["summary"]["scanned"]["scanned_files"]) == {
        "malicious1.zip:data.pkl",
        "malicious0.pkl",
        "malicious3.pkl",
        "malicious6.pkl",
        "malicious7.pkl",
        "malicious8.pkl",
        "malicious9.pkl",
        "malicious10.pkl",
        "malicious11.pkl",
        "malicious12.pkl",
        "malicious13.pkl",
        "malicious14.pkl",
        "malicious15.pkl",
        "malicious1_v0.dill",
        "malicious1_v3.dill",
        "malicious1_v4.dill",
        "malicious4.pickle",
        "malicious5.pickle",
        "malicious1_v0.pkl",
        "malicious1_v3.pkl",
        "malicious1_v4.pkl",
        "malicious2_v0.pkl",
        "malicious2_v3.pkl",
        "malicious2_v4.pkl",
        "benign0_v0.pkl",
        "benign0_v3.pkl",
        "benign0_v4.pkl",
        "benign0_v0.dill",
        "benign0_v3.dill",
        "benign0_v4.dill",
    }
    assert results["summary"]["skipped"]["skipped_files"] == []
    assert results["errors"] == []


@pytest.mark.parametrize(
    "file_extension", [".h5", ".keras", ".pb"], ids=["h5", "keras", "pb"]
)
def test_scan_keras(keras_file_path: Any, file_extension: str) -> None:
    keras_file_path_parent_dir, safe_saved_model_dir, unsafe_saved_model_dir = (
        keras_file_path[0],
        keras_file_path[1],
        keras_file_path[2],
    )
    ms = ModelScan()
    results = {}
    safe_filename = ""
    if file_extension == ".pb":
        safe_filename = f"{safe_saved_model_dir}"
    else:
        safe_filename = f"{keras_file_path_parent_dir}/safe{file_extension}"

    results = ms.scan(Path(safe_filename))

    assert ms.issues.all_issues == []

    if file_extension == ".pb":
        assert set(results["summary"]["scanned"]["scanned_files"]) == {
            "fingerprint.pb",
            "keras_metadata.pb",
            "saved_model.pb",
        }

        assert set(
            [
                skipped_file["source"]
                for skipped_file in results["summary"]["skipped"]["skipped_files"]
            ]
        ) == {
            "variables/variables.data-00000-of-00001",
            "variables/variables.index",
        }
        assert results["errors"] == []

    else:
        assert results["summary"]["scanned"]["scanned_files"] == [
            f"safe{file_extension}"
        ]

        if file_extension == ".keras":
            assert set(
                [
                    skipped_file["source"]
                    for skipped_file in results["summary"]["skipped"]["skipped_files"]
                ]
            ) == {
                f"safe{file_extension}:metadata.json",
                f"safe{file_extension}:config.json",
                f"safe{file_extension}:model.weights.h5",
            }
        else:
            assert results["summary"]["skipped"]["skipped_files"] == []

        assert results["errors"] == []

    unsafe_filename = ""
    if file_extension == ".keras":
        unsafe_filename = f"{keras_file_path_parent_dir}/unsafe{file_extension}"
        expected = [
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    IssueSeverity.MEDIUM,
                    f"{keras_file_path_parent_dir}/unsafe{file_extension}:config.json",
                ),
            ),
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    IssueSeverity.MEDIUM,
                    f"{keras_file_path_parent_dir}/unsafe{file_extension}:config.json",
                ),
            ),
        ]
        results = ms.scan(Path(f"{keras_file_path_parent_dir}/unsafe{file_extension}"))

        assert ms.issues.all_issues == expected

    elif file_extension == ".pb":
        file_name = "keras_metadata.pb"
        unsafe_filename = f"{unsafe_saved_model_dir}"
        expected = [
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    IssueSeverity.MEDIUM,
                    f"{unsafe_saved_model_dir}/{file_name}",
                ),
            ),
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    IssueSeverity.MEDIUM,
                    f"{unsafe_saved_model_dir}/{file_name}",
                ),
            ),
        ]
        results = ms.scan(Path(f"{unsafe_saved_model_dir}"))
        assert ms.issues.all_issues == expected
        assert results["errors"] == []
        assert set(results["summary"]["scanned"]["scanned_files"]) == {
            "fingerprint.pb",
            "keras_metadata.pb",
            "saved_model.pb",
        }
        assert set(
            [
                skipped_file["source"]
                for skipped_file in results["summary"]["skipped"]["skipped_files"]
            ]
        ) == {
            "variables/variables.data-00000-of-00001",
            "variables/variables.index",
        }
    else:
        unsafe_filename = f"{keras_file_path_parent_dir}/unsafe{file_extension}"
        expected = [
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    IssueSeverity.MEDIUM,
                    f"{keras_file_path_parent_dir}/unsafe{file_extension}",
                ),
            ),
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    IssueSeverity.MEDIUM,
                    f"{keras_file_path_parent_dir}/unsafe{file_extension}",
                ),
            ),
        ]

        results = ms.scan(Path(f"{keras_file_path_parent_dir}/unsafe{file_extension}"))

        assert ms.issues.all_issues == expected
        assert results["errors"] == []
        assert results["summary"]["skipped"]["skipped_files"] == []
        if file_extension == ".keras":
            assert set(results["summary"]["scanned"]["scanned_files"]) == {
                f"unsafe{file_extension}",
                f"unsafe{file_extension}:model.weights.h5",
            }

        else:
            assert results["summary"]["scanned"]["scanned_files"] == [
                f"unsafe{file_extension}"
            ]


def test_scan_tensorflow(tensorflow_file_path: Any) -> None:
    safe_tensorflow_model_dir, unsafe_tensorflow_model_dir = (
        tensorflow_file_path[0],
        tensorflow_file_path[1],
    )
    ms = ModelScan()
    results = ms.scan(Path(f"{safe_tensorflow_model_dir}"))
    assert ms.issues.all_issues == []
    assert set(results["summary"]["scanned"]["scanned_files"]) == {
        "fingerprint.pb",
        "keras_metadata.pb",
        "saved_model.pb",
    }
    assert set(
        [
            skipped_file["source"]
            for skipped_file in results["summary"]["skipped"]["skipped_files"]
        ]
    ) == {
        "variables/variables.data-00000-of-00001",
        "variables/variables.index",
    }
    assert results["errors"] == []

    file_name = "saved_model.pb"
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "Tensorflow",
                "ReadFile",
                IssueSeverity.HIGH,
                f"{unsafe_tensorflow_model_dir}/{file_name}",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "Tensorflow",
                "WriteFile",
                IssueSeverity.HIGH,
                f"{unsafe_tensorflow_model_dir}/{file_name}",
            ),
        ),
    ]
    results = ms.scan(Path(f"{unsafe_tensorflow_model_dir}"))

    assert ms.issues.all_issues == expected
    assert set(results["summary"]["scanned"]["scanned_files"]) == {
        "fingerprint.pb",
        "keras_metadata.pb",
        "saved_model.pb",
    }
    assert set(
        [
            skipped_file["source"]
            for skipped_file in results["summary"]["skipped"]["skipped_files"]
        ]
    ) == {
        "variables/variables.data-00000-of-00001",
        "variables/variables.index",
    }
    assert results["errors"] == []


def test_main(file_path: Any) -> None:
    argv = sys.argv
    try:
        sys.argv = ["modelscan", "scan", "-p", f"{file_path}/data/benign0_v3.pkl"]
        assert cli() == 0
        importlib.import_module("modelscan.scanner")
    except SystemExit:
        pass
    finally:
        sys.argv = argv


def test_main_defaultgroup(file_path: Any) -> None:
    argv = sys.argv
    try:
        sys.argv = ["modelscan", "-p", f"{file_path}/data/benign0_v3.pkl"]
        assert cli() == 0
        importlib.import_module("modelscan.scanner")
    except SystemExit:
        pass
    finally:
        sys.argv = argv
