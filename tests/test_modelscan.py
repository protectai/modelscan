import aiohttp
import http.client
import importlib
import io
import numpy as np
import os
from pathlib import Path
import pickle
import pytest
import requests  # type: ignore[import]
import socket
import subprocess
import sys
import tensorflow as tf
from tensorflow import keras
from typing import Any, List, Set
from test_utils import generate_dill_unsafe_file
import zipfile

from modelscan.modelscan import Modelscan
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


def initialize_data_file(path: str, data: Any) -> None:
    if not os.path.exists(path):
        with open(path, "wb") as file:
            file.write(data)


def initialize_zip_file(path: str, file_name: str, data: Any) -> None:
    if not os.path.exists(path):
        with zipfile.ZipFile(path, "w") as zip:
            zip.writestr(file_name, data)


def initialize_numpy_file(path: str) -> None:
    import numpy as np

    # create numpy object array
    with open(path, "wb") as f:
        data = [(1, 2), (3, 4)]
        x = np.empty((2, 2), dtype=object)
        x[:] = data
        np.save(f, x)


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
def pickle_file_path(tmp_path_factory: Any) -> Any:
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

    initialize_numpy_file(f"{tmp}/data/object_array.npy")

    return tmp


@pytest.fixture(scope="session")
def keras_file_path(tmp_path_factory: Any) -> Any:
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
    keras_model.save(f"{tmp}/safe.h5")

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
    new_layer = keras.layers.Lambda(attack)(input_to_new_layer)

    malicious_model = tf.keras.Model(inputs=keras_model.inputs, outputs=[new_layer])
    malicious_model.compile(optimizer="adam", loss="mean_squared_error")

    malicious_model.save(f"{tmp}/unsafe.h5")

    return tmp


def compare_results(resultList: List[Issue], expectedSet: Set[Issue]) -> None:
    for result in resultList:
        assert result in expectedSet


def test_scan_pickle_bytes() -> None:
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails("builtins", "eval", "file.pkl"),
        )
    ]
    assert (
        scan_pickle_bytes(io.BytesIO(pickle.dumps(Malicious1())), "file.pkl")[0]
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

    ms = Modelscan()
    ms._scan_zip(f"{zip_file_path}/test.zip")
    assert ms.issues.all_issues == expected


def test_scan_numpy(pickle_file_path: Any) -> None:
    expected = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "numpy.core.multiarray", "_reconstruct", "object_array.npy"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails("numpy", "ndarray", "object_array.npy"),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails("numpy", "dtype", "object_array.npy"),
        ),
    }
    with open(f"{pickle_file_path}/data/object_array.npy", "rb") as f:
        compare_results(
            scan_numpy(io.BytesIO(f.read()), "object_array.npy")[0], expected
        )


def test_scan_file_path(pickle_file_path: Any) -> None:
    benign = Modelscan()
    benign.scan_path(Path(f"{pickle_file_path}/data/benign0_v3.pkl"))
    assert benign.issues.all_issues == []

    malicious0 = Modelscan()
    expected_malicious0 = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "__builtin__", "dict", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "apply", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "compile", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "__builtin__", "globals", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "getattr", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
    }
    malicious0.scan_path(Path(f"{pickle_file_path}/data/malicious0.pkl"))
    compare_results(malicious0.issues.all_issues, expected_malicious0)

    expected_malicious1_v0 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{pickle_file_path}/data/malicious1_v0.pkl"
            ),
        )
    ]
    expected_malicious1_v3 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{pickle_file_path}/data/malicious1_v3.pkl"
            ),
        )
    ]
    expected_malicious1_v4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{pickle_file_path}/data/malicious1_v4.pkl"
            ),
        )
    ]
    expected_malicious1 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{pickle_file_path}/data/malicious1.zip:data.pkl"
            ),
        )
    ]
    malicious1_v0 = Modelscan()
    malicious1_v3 = Modelscan()
    malicious1_v4 = Modelscan()
    malicious1 = Modelscan()
    malicious1_v0.scan_path(Path(f"{pickle_file_path}/data/malicious1_v0.pkl"))
    malicious1_v3.scan_path(Path(f"{pickle_file_path}/data/malicious1_v3.pkl"))
    malicious1_v4.scan_path(Path(f"{pickle_file_path}/data/malicious1_v4.pkl"))
    malicious1.scan_path(Path(f"{pickle_file_path}/data/malicious1.zip"))
    assert malicious1_v0.issues.all_issues == expected_malicious1_v0
    assert malicious1_v3.issues.all_issues == expected_malicious1_v3
    assert malicious1_v4.issues.all_issues == expected_malicious1_v4
    assert malicious1.issues.all_issues == expected_malicious1

    expected_malicious2_v0 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{pickle_file_path}/data/malicious2_v0.pkl"
            ),
        )
    ]
    expected_malicious2_v3 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{pickle_file_path}/data/malicious2_v3.pkl"
            ),
        )
    ]
    expected_malicious2_v4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{pickle_file_path}/data/malicious2_v4.pkl"
            ),
        )
    ]
    malicious2_v0 = Modelscan()
    malicious2_v3 = Modelscan()
    malicious2_v4 = Modelscan()
    malicious2_v0.scan_path(Path(f"{pickle_file_path}/data/malicious2_v0.pkl"))
    malicious2_v3.scan_path(Path(f"{pickle_file_path}/data/malicious2_v3.pkl"))
    malicious2_v4.scan_path(Path(f"{pickle_file_path}/data/malicious2_v4.pkl"))
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
                Path(f"{pickle_file_path}/data/malicious3.pkl"),
            ),
        )
    ]
    malicious3 = Modelscan()
    malicious3.scan_path(Path(f"{pickle_file_path}/data/malicious3.pkl"))
    assert malicious3.issues.all_issues == expected_malicious3

    expected_malicious4 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api", "get", f"{pickle_file_path}/data/malicious4.pickle"
            ),
        )
    ]
    malicious4 = Modelscan()
    malicious4.scan_path(Path(f"{pickle_file_path}/data/malicious4.pickle"))
    assert malicious4.issues.all_issues == expected_malicious4

    expected_malicious5 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "aiohttp.client",
                "ClientSession",
                f"{pickle_file_path}/data/malicious5.pickle",
            ),
        )
    ]
    malicious5 = Modelscan()
    malicious5.scan_path(Path(f"{pickle_file_path}/data/malicious5.pickle"))
    assert malicious5.issues.all_issues == expected_malicious5

    expected_malicious6 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api", "get", f"{pickle_file_path}/data/malicious6.pkl"
            ),
        )
    ]
    malicious6 = Modelscan()
    malicious6.scan_path(Path(f"{pickle_file_path}/data/malicious6.pkl"))
    assert malicious6.issues.all_issues == expected_malicious6

    expected_malicious7 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "socket", "create_connection", f"{pickle_file_path}/data/malicious7.pkl"
            ),
        )
    ]
    malicious7 = Modelscan()
    malicious7.scan_path(Path(f"{pickle_file_path}/data/malicious7.pkl"))
    assert malicious7.issues.all_issues == expected_malicious7

    expected_malicious8 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "subprocess", "run", f"{pickle_file_path}/data/malicious8.pkl"
            ),
        )
    ]
    malicious8 = Modelscan()
    malicious8.scan_path(Path(f"{pickle_file_path}/data/malicious8.pkl"))
    assert malicious8.issues.all_issues == expected_malicious8

    expected_malicious9 = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "sys", "exit", f"{pickle_file_path}/data/malicious9.pkl"
            ),
        )
    ]
    malicious9 = Modelscan()
    malicious9.scan_path(Path(f"{pickle_file_path}/data/malicious9.pkl"))
    assert malicious9.issues.all_issues == expected_malicious9


def test_scan_directory_path(pickle_file_path: str) -> None:
    expected = {
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{pickle_file_path}/data/malicious1.zip:data.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "subprocess", "run", f"{pickle_file_path}/data/malicious8.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "sys", "exit", f"{pickle_file_path}/data/malicious9.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api", "get", f"{pickle_file_path}/data/malicious4.pickle"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{pickle_file_path}/data/malicious1_v3.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{pickle_file_path}/data/malicious1_v0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "builtins", "eval", f"{pickle_file_path}/data/malicious1_v4.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "numpy", "ndarray", f"{pickle_file_path}/data/object_array.npy"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "numpy", "dtype", f"{pickle_file_path}/data/object_array.npy"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "numpy", "dtype", f"{pickle_file_path}/data/object_array.npy"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "numpy.core.multiarray",
                "_reconstruct",
                f"{pickle_file_path}/data/object_array.npy",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "aiohttp.client",
                "ClientSession",
                f"{pickle_file_path}/data/malicious5.pickle",
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{pickle_file_path}/data/malicious2_v4.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "socket", "create_connection", f"{pickle_file_path}/data/malicious7.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "requests.api", "get", f"{pickle_file_path}/data/malicious6.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "compile", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "eval", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "__builtin__", "globals", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "apply", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__", "getattr", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "__builtin__", "dict", f"{pickle_file_path}/data/malicious0.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{pickle_file_path}/data/malicious2_v3.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.HIGH,
            OperatorIssueDetails(
                "httplib", "HTTPSConnection", f"{pickle_file_path}/data/malicious3.pkl"
            ),
        ),
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "posix", "system", f"{pickle_file_path}/data/malicious2_v0.pkl"
            ),
        ),
    }
    ms = Modelscan()
    p = Path(f"{pickle_file_path}/data/")
    ms.scan_path(p)
    compare_results(ms.issues.all_issues, expected)


def test_scan_huggingface_model() -> None:
    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.CRITICAL,
            OperatorIssueDetails(
                "__builtin__",
                "eval",
                "https://huggingface.co/ykilcher/totally-harmless-model/resolve/main/pytorch_model.bin:archive/data.pkl",
            ),
        )
    ]
    ms = Modelscan()
    ms.scan_huggingface_model("ykilcher/totally-harmless-model")
    assert ms.issues.all_issues == expected


# def test_scan_tf() -> None:


def test_scan_keras(keras_file_path: Any) -> None:
    ms = Modelscan()
    ms.scan_path(Path(f"{keras_file_path}/safe.h5"))
    assert ms.issues.all_issues == []

    expected = [
        Issue(
            IssueCode.UNSAFE_OPERATOR,
            IssueSeverity.MEDIUM,
            OperatorIssueDetails(
                "Keras",
                "Lambda",
                f"{keras_file_path}/unsafe.h5",
            ),
        )
    ]
    ms.scan_path(Path(f"{keras_file_path}/unsafe.h5"))
    assert ms.issues.all_issues == expected


def test_main(pickle_file_path: Any) -> None:
    argv = sys.argv
    try:
        sys.argv = ["modelscan", "-p", f"{pickle_file_path}/data/benign0_v3.pkl"]
        assert cli() == 0
        importlib.import_module("modelscan.scanner")
    except SystemExit:
        pass
    finally:
        sys.argv = argv
