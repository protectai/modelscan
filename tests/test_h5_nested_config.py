"""Regression tests for the H5 model_config nested-module-reference bypass.

Before the fix, ``H5LambdaDetectScan`` only inspected top-level layers for
``class_name == "Lambda"``. An attacker-controlled module reference hidden in a
nested config object (e.g. a ``kernel_initializer`` with
``module="builtins", class_name="exec"``) was reported as "0 issues" — a true
false negative — even though Keras resolves that module via importlib when the
model is loaded with ``tf.keras.models.load_model(..., safe_mode=False)``.
"""

import json
from pathlib import Path
from typing import Any, Dict

import pytest

h5py = pytest.importorskip("h5py")

from modelscan.modelscan import ModelScan  # noqa: E402
from modelscan.issues import IssueCode  # noqa: E402


def _write_h5_with_model_config(path: Path, model_config: Dict[str, Any]) -> None:
    with h5py.File(path, "w") as f:
        f.attrs["model_config"] = json.dumps(model_config)


def _nested_malicious_config() -> Dict[str, Any]:
    # A standard Sequential model with no Lambda layer, but a Dense layer whose
    # kernel_initializer references a non-Keras module. This is the exact shape
    # the bypass exploited.
    return {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "class_name": "Dense",
                    "config": {
                        "name": "dense",
                        "units": 8,
                        "kernel_initializer": {
                            "module": "builtins",
                            "class_name": "exec",
                            "config": {"code": "print('pwned')"},
                            "registered_name": "exec",
                        },
                    },
                }
            ],
        },
    }


def _benign_config() -> Dict[str, Any]:
    return {
        "class_name": "Sequential",
        "config": {
            "name": "sequential",
            "layers": [
                {
                    "class_name": "Dense",
                    "config": {
                        "name": "dense",
                        "units": 8,
                        "kernel_initializer": {
                            "module": "keras.initializers",
                            "class_name": "GlorotUniform",
                            "config": {"seed": None},
                            "registered_name": None,
                        },
                    },
                }
            ],
        },
    }


def test_h5_nested_unsafe_module_detected(tmp_path: Path) -> None:
    malicious = tmp_path / "malicious.h5"
    _write_h5_with_model_config(malicious, _nested_malicious_config())

    ms = ModelScan()
    ms.scan(malicious)

    # The file must be scanned (not skipped) and the nested module flagged.
    unsafe_ops = [
        issue
        for issue in ms.issues.all_issues
        if issue.code == IssueCode.UNSAFE_OPERATOR
    ]
    assert unsafe_ops, "nested unsafe module reference was not detected (false negative)"
    assert any(
        "builtins.exec" in issue.details.operator for issue in unsafe_ops
    ), "the builtins.exec reference should appear in the flagged operator"


def test_h5_benign_keras_module_not_flagged(tmp_path: Path) -> None:
    benign = tmp_path / "benign.h5"
    _write_h5_with_model_config(benign, _benign_config())

    ms = ModelScan()
    ms.scan(benign)

    unsafe_ops = [
        issue
        for issue in ms.issues.all_issues
        if issue.code == IssueCode.UNSAFE_OPERATOR
    ]
    assert not unsafe_ops, "a standard keras.initializers reference must not be flagged"
