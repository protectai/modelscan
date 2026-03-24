"""Test that modelscan detects unsafe module references in .keras config.json.

Verifies that the scanner catches non-Keras module references embedded in
nested config objects (initializers, regularizers, etc.), not just top-level
Lambda layers.
"""

import json
import zipfile
import io
import pytest


def _make_keras_zip(config: dict) -> io.BytesIO:
    """Create an in-memory .keras zip with the given config.json."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("config.json", json.dumps(config))
    buf.seek(0)
    return buf


SAFE_CONFIG = {
    "module": "keras",
    "class_name": "Sequential",
    "config": {
        "name": "sequential",
        "layers": [
            {
                "module": "keras.layers",
                "class_name": "Dense",
                "config": {
                    "units": 1,
                    "kernel_initializer": {
                        "module": "keras.initializers",
                        "class_name": "GlorotUniform",
                        "config": {"seed": None},
                        "registered_name": None,
                    },
                },
                "registered_name": None,
            }
        ],
    },
    "registered_name": None,
}

MALICIOUS_NESTED_CONFIG = {
    "module": "keras",
    "class_name": "Sequential",
    "config": {
        "name": "sequential",
        "layers": [
            {
                "module": "keras.layers",
                "class_name": "Dense",
                "config": {
                    "units": 1,
                    "kernel_initializer": {
                        "module": "builtins",
                        "class_name": "exec",
                        "config": {},
                        "registered_name": None,
                    },
                },
                "registered_name": None,
            }
        ],
    },
    "registered_name": None,
}

MALICIOUS_TOP_LEVEL_MODULE = {
    "module": "keras",
    "class_name": "Sequential",
    "config": {
        "name": "sequential",
        "layers": [
            {
                "module": "subprocess",
                "class_name": "Popen",
                "config": {"name": "exploit"},
                "registered_name": None,
            }
        ],
    },
    "registered_name": None,
}


class TestExtractUnsafeModules:
    """Test the _extract_unsafe_modules static method directly."""

    def test_safe_config_returns_empty(self):
        from modelscan.scanners.keras.scan import KerasLambdaDetectScan

        result = KerasLambdaDetectScan._extract_unsafe_modules(SAFE_CONFIG)
        assert result == []

    def test_nested_builtins_exec_detected(self):
        from modelscan.scanners.keras.scan import KerasLambdaDetectScan

        result = KerasLambdaDetectScan._extract_unsafe_modules(MALICIOUS_NESTED_CONFIG)
        assert len(result) == 1
        assert "builtins.exec" in result[0]

    def test_top_level_subprocess_detected(self):
        from modelscan.scanners.keras.scan import KerasLambdaDetectScan

        result = KerasLambdaDetectScan._extract_unsafe_modules(
            MALICIOUS_TOP_LEVEL_MODULE
        )
        assert len(result) == 1
        assert "subprocess.Popen" in result[0]

    def test_tensorflow_modules_are_safe(self):
        from modelscan.scanners.keras.scan import KerasLambdaDetectScan

        config = {
            "module": "tensorflow.python.ops",
            "class_name": "Operation",
            "config": {},
        }
        result = KerasLambdaDetectScan._extract_unsafe_modules(config)
        assert result == []
