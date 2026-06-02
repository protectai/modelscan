import io
import json
import zipfile
from types import SimpleNamespace

from modelscan.model import Model
from modelscan.issues import IssueSeverity
from modelscan.scanners.keras.scan import KerasLambdaDetectScan
from modelscan.settings import DEFAULT_SETTINGS, SupportedModelFormats


def test_keras_scan_detects_nested_lambda_layers() -> None:
    model_config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {
                    "class_name": "Functional",
                    "config": {
                        "layers": [
                            {
                                "class_name": "InputLayer",
                                "config": {"name": "nested_input"},
                            },
                            {
                                "class_name": "Lambda",
                                "config": {"name": "nested_lambda"},
                            },
                        ]
                    },
                }
            ]
        },
    }
    model = Model(
        "nested.keras:config.json", io.BytesIO(json.dumps(model_config).encode())
    )

    assert KerasLambdaDetectScan({})._get_keras_operator_names(model) == ["Lambda"]


def test_keras_scanner_reports_nested_lambda_layers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from modelscan.scanners.saved_model import scan as saved_model_scan

    monkeypatch.setattr(saved_model_scan, "tensorflow_installed", True)
    monkeypatch.setattr(
        saved_model_scan,
        "tensorflow",
        SimpleNamespace(raw_ops=SimpleNamespace()),
        raising=False,
    )

    model_config = {
        "class_name": "Functional",
        "config": {
            "layers": [
                {
                    "class_name": "Functional",
                    "config": {
                        "layers": [
                            {
                                "class_name": "Lambda",
                                "config": {"name": "nested_lambda"},
                            }
                        ]
                    },
                }
            ]
        },
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as model_zip:
        model_zip.writestr("config.json", json.dumps(model_config))
    archive.seek(0)

    model = Model("nested.keras", archive)
    model.set_context("formats", [SupportedModelFormats.KERAS])

    result = KerasLambdaDetectScan(DEFAULT_SETTINGS).scan(model)

    assert result is not None
    assert len(result.issues) == 1
    assert result.issues[0].details.operator == "Lambda"
    assert result.issues[0].severity == IssueSeverity.MEDIUM
