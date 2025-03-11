import tomlkit
from typing import Any
from modelscan._version import __version__

class Property:
    def __init__(self, name: str, value: Any) -> None:
        self.name = name
        self.value = value


class SupportedModelFormats:
    SAFETENSORS = Property("SAFETENSORS", "safetensors")
    TENSORFLOW = Property("TENSORFLOW", "tensorflow")
    KERAS_H5 = Property("KERAS_H5", "keras_h5")
    KERAS = Property("KERAS", "keras")
    NUMPY = Property("NUMPY", "numpy")
    PYTORCH = Property("PYTORCH", "pytorch")
    PICKLE = Property("PICKLE", "pickle")
    GENERIC = Property("GENERIC", "generic")
      # Added Safetensor format


DEFAULT_REPORTING_MODULES = {
    "console": "modelscan.reports.ConsoleReport",
    "json": "modelscan.reports.JSONReport",
}

DEFAULT_SETTINGS = {
    "modelscan_version": __version__,
    "supported_zip_extensions": [".zip", ".npz"],
    "scanners": {
        "modelscan.scanners.SafetensorUnsafeScan": {
            "enabled": True,
            "supported_extensions": [".safetensors"],
        },
        "modelscan.scanners.H5LambdaDetectScan": {
            "enabled": True,
            "supported_extensions": [".h5"],
        },
        "modelscan.scanners.KerasLambdaDetectScan": {
            "enabled": True,
            "supported_extensions": [".keras"],
        },
        "modelscan.scanners.SavedModelLambdaDetectScan": {
            "enabled": True,
            "supported_extensions": [".pb"],
            "unsafe_keras_operators": {
                "Lambda": "MEDIUM",
            },
        },
        "modelscan.scanners.SavedModelTensorflowOpScan": {
            "enabled": True,
            "supported_extensions": [".pb"],
            "unsafe_tf_operators": {
                "ReadFile": "HIGH",
                "WriteFile": "HIGH",
            },
        },
        "modelscan.scanners.NumpyUnsafeOpScan": {
            "enabled": True,
            "supported_extensions": [".npy"],
        },
        "modelscan.scanners.PickleUnsafeOpScan": {
            "enabled": True,
            "supported_extensions": [
                ".pkl",
                ".pickle",
                ".joblib",
                ".dill",
                ".dat",
                ".data",
            ],
        },
        "modelscan.scanners.PyTorchUnsafeOpScan": {
            "enabled": True,
            "supported_extensions": [".bin", ".pt", ".pth", ".ckpt"],
        },
        "modelscan.scanners.GenericUnsafeScan": {
            "enabled": True,
            "supported_extensions": [".json",".md",".txt",".msgpack",".onnx"],
    },
    },
    "middlewares": {
        "modelscan.middlewares.FormatViaExtensionMiddleware": {
            "formats": {
                SupportedModelFormats.TENSORFLOW: [".pb"],
                SupportedModelFormats.KERAS_H5: [".h5"],
                SupportedModelFormats.KERAS: [".keras"],
                SupportedModelFormats.NUMPY: [".npy"],
                SupportedModelFormats.PYTORCH: [".bin", ".pt", ".pth", ".ckpt"],
                SupportedModelFormats.PICKLE: [
                    ".pkl",
                    ".pickle",
                    ".joblib",
                    ".dill",
                    ".dat",
                    ".data",
                ],
                SupportedModelFormats.SAFETENSORS: [".safetensors"],  # Added SafeTensor extensions
                SupportedModelFormats.GENERIC: [".json",".md",".txt",".msgpack",".onnx"], # Added Generic extensions
            }
        }
    },
    "unsafe_globals": {
        "CRITICAL": {
            "__builtin__": [
                "eval",
                "compile",
                "getattr",
                "apply",
                "exec",
                "open",
                "breakpoint",
                "__import__",
            ],
            "builtins": [
                "eval",
                "compile",
                "getattr",
                "apply",
                "exec",
                "open",
                "breakpoint",
                "__import__",
            ],
            "runpy": "*",
            "os": "*",
            "nt": "*",
            "posix": "*",
            "socket": "*",
            "subprocess": "*",
            "sys": "*",
            "operator": [
                "attrgetter",
            ],
            "pty": "*",
            "pickle": "*",
            "bdb": "*",
            "pdb": "*",
            "shutil": "*",
            "asyncio": "*",
        },
        "HIGH": {
            "webbrowser": "*",
            "httplib": "*",
            "requests.api": "*",
            "aiohttp.client": "*",
        },
        "MEDIUM": {},
        "LOW": {},
    },
    "reporting": {
        "module": "modelscan.reports.ConsoleReport",
        "settings": {},
    },
}


class SettingsUtils:
    @staticmethod
    def get_default_settings_as_toml() -> Any:
        toml_settings = tomlkit.dumps(DEFAULT_SETTINGS)

        # Add settings file header
        toml_settings = f"# ModelScan settings file\n\n{toml_settings}"

        return toml_settings
