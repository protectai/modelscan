import aiohttp
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
import tensorflow as tf
from tensorflow import keras
from typing import Any, List, Set, Dict
from test_utils import generate_dill_unsafe_file, generate_unsafe_pickle_file
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
    scan_numpy,
)
from modelscan.settings import DEFAULT_SETTINGS

settings: Dict[str, Any] = DEFAULT_SETTINGS["scanners"]  # type: ignore[assignment]


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

    initialize_zip_file(
        f"{tmp}/data/malicious1.zip",
        "data.pkl",
        pickle.dumps(Malicious1(), protocol=4),
    )

    malicious10_pickle_bytes = (
        b"(S'print(\"Injection running\")'\ni__builtin__\nexec\n."
    )
    initialize_data_file(f"{tmp}/data/malicious10.pkl", malicious10_pickle_bytes)

    return tmp


@pytest.fixture(scope="session")
def keras_file_extensions() -> List[str]:
    return ["h5", "keras"]


@pytest.fixture(scope="session")
def keras_file_path(tmp_path_factory: Any, keras_file_extensions: List[str]) -> Any:
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

    malicious_model = tf.keras.Model(
        inputs=keras_model.inputs, outputs=[second_lambda_layer]
    )
    malicious_model.compile(optimizer="adam", loss="mean_squared_error")

    for extension in keras_file_extensions:
        malicious_model.save(f"{tmp}/unsafe.{extension}")

    return tmp


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
            OperatorIssueDetails("builtins", "eval", "file.pkl"),
        )
    ]
    assert (
        scan_pickle_bytes(
            io.BytesIO(pickle.dumps(Malicious1())), "file.pkl", settings
        ).issues
        == expected
    )


def test_scan_zip(zip_file_path: Any) -> None:
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{zip_file_path}/test.zip:data.pkl"
            ),
        )
    ]

    ms = ModelScan()
    ms._scan_zip(f"{zip_file_path}/test.zip")
    assert ms.issues.all_issues == expected


def test_scan_pytorch(pytorch_file_path: Any) -> None:
    bad_pytorch = ModelScan()
    bad_pytorch.scan(Path(f"{pytorch_file_path}/bad_pytorch.pt"))
    assert bad_pytorch.issues.all_issues == []
    assert [error.scan_name for error in bad_pytorch.errors] == ["pytorch"]  # type: ignore[attr-defined]


def test_scan_numpy(numpy_file_path: Any) -> None:
    with open(f"{numpy_file_path}/safe_numpy.npy", "rb") as f:
        assert scan_numpy(io.BytesIO(f.read()), "safe_numpy.npy", settings).issues == []

    expected = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails("builtins", "exec", "unsafe_numpy.npy"),
        ),
    }

    with open(f"{numpy_file_path}/unsafe_numpy.npy", "rb") as f:
        compare_results(
            scan_numpy(io.BytesIO(f.read()), "unsafe_numpy.npy", settings).issues,
            expected,
        )


def test_scan_file_path(file_path: Any) -> None:
    benign_pickle = ModelScan()
    benign_pickle.scan(Path(f"{file_path}/data/benign0_v3.pkl"))
    benign_dill = ModelScan()
    benign_dill.scan(Path(f"{file_path}/data/benign0_v3.dill"))
    assert benign_pickle.issues.all_issues == []
    assert benign_dill.issues.all_issues == []

    malicious0 = ModelScan()
    expected_malicious0 = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "apply", f"{file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "compile", f"{file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "getattr", f"{file_path}/data/malicious0.pkl"
            ),
        ),
    }
    malicious0.scan(Path(f"{file_path}/data/malicious0.pkl"))
    compare_results(malicious0.issues.all_issues, expected_malicious0)


def test_scan_pickle_operators(file_path: Any) -> None:
    # Tests the unsafe pickle operators we screen for, across differences in pickle versions 0-2, 3, and 4
    expected_malicious1_v0 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{file_path}/data/malicious1_v0.pkl"
            ),
        )
    ]
    expected_malicious1_v3 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v3.pkl"
            ),
        )
    ]
    expected_malicious1_v4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v4.pkl"
            ),
        )
    ]
    # dill based malicious1
    expected_malicious1_v0_dill = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{file_path}/data/malicious1_v0.dill"
            ),
        )
    ]
    expected_malicious1_v3_dill = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v3.dill"
            ),
        )
    ]
    expected_malicious1_v4_dill = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v4.dill"
            ),
        )
    ]

    expected_malicious1 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1.zip:data.pkl"
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
                "posix", "system", f"{file_path}/data/malicious2_v0.pkl"
            ),
        )
    ]
    expected_malicious2_v3 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{file_path}/data/malicious2_v3.pkl"
            ),
        )
    ]
    expected_malicious2_v4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{file_path}/data/malicious2_v4.pkl"
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
                "requests.api", "get", f"{file_path}/data/malicious4.pickle"
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
                "requests.api", "get", f"{file_path}/data/malicious6.pkl"
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
                "socket", "create_connection", f"{file_path}/data/malicious7.pkl"
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
                "subprocess", "run", f"{file_path}/data/malicious8.pkl"
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
            OperatorIssueDetails("sys", "exit", f"{file_path}/data/malicious9.pkl"),
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
                "__builtin__", "exec", f"{file_path}/data/malicious10.pkl"
            ),
        )
    ]
    malicious10 = ModelScan()
    malicious10.scan(Path(f"{file_path}/data/malicious10.pkl"))
    assert malicious10.issues.all_issues == expected_malicious10


def test_scan_directory_path(file_path: str) -> None:
    expected = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1.zip:data.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "subprocess", "run", f"{file_path}/data/malicious8.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails("sys", "exit", f"{file_path}/data/malicious9.pkl"),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api", "get", f"{file_path}/data/malicious4.pickle"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v3.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{file_path}/data/malicious1_v0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v4.pkl"
            ),
        ),
        # dill based expected issues
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v3.dill"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{file_path}/data/malicious1_v0.dill"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{file_path}/data/malicious1_v4.dill"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "aiohttp.client",
                "ClientSession",
                f"{file_path}/data/malicious5.pickle",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{file_path}/data/malicious2_v4.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "socket", "create_connection", f"{file_path}/data/malicious7.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api", "get", f"{file_path}/data/malicious6.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "compile", f"{file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "apply", f"{file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "getattr", f"{file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{file_path}/data/malicious2_v3.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "httplib", "HTTPSConnection", f"{file_path}/data/malicious3.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{file_path}/data/malicious2_v0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "exec", f"{file_path}/data/malicious10.pkl"
            ),
        ),
    }
    ms = ModelScan()
    p = Path(f"{file_path}/data/")
    ms.scan(p)
    compare_results(ms.issues.all_issues, expected)


@pytest.mark.parametrize("file_extension", [".h5", ".keras"], ids=["h5", "keras"])
def test_scan_keras(keras_file_path: Any, file_extension: str) -> None:
    ms = ModelScan()
    ms.scan(Path(f"{keras_file_path}/safe{file_extension}"))
    assert ms.issues.all_issues == []

    if file_extension == ".keras":
        expected = [
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    f"{keras_file_path}/unsafe{file_extension}:config.json",
                ),
            ),
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    f"{keras_file_path}/unsafe{file_extension}:config.json",
                ),
            ),
        ]
        ms._scan_source(
            Path(f"{keras_file_path}/unsafe{file_extension}"),
        )
    else:
        expected = [
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    f"{keras_file_path}/unsafe{file_extension}",
                ),
            ),
            Issue(
                IssueCode.UNSAFE_OPERATOR,
                IssueSeverity.MEDIUM,
                OperatorIssueDetails(
                    "Keras",
                    "Lambda",
                    f"{keras_file_path}/unsafe{file_extension}",
                ),
            ),
        ]
        ms._scan_path(Path(f"{keras_file_path}/unsafe{file_extension}"))

    assert ms.issues.all_issues == expected


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
