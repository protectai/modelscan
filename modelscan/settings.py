import tomlkit

from typing import Any

from modelscan._version import __version__


class Property:
    def __init__(self, name: str, value: Any) -> None:
        self.name = name
        self.value = value


class SupportedModelFormats:
    TENSORFLOW = Property("TENSORFLOW", "tensorflow")
    KERAS_H5 = Property("KERAS_H5", "keras_h5")
    KERAS = Property("KERAS", "keras")
    NUMPY = Property("NUMPY", "numpy")
    PYTORCH = Property("PYTORCH", "pytorch")
    PICKLE = Property("PICKLE", "pickle")


DEFAULT_REPORTING_MODULES = {
    "console": "modelscan.reports.ConsoleReport",
    "json": "modelscan.reports.JSONReport",
}

DEFAULT_SETTINGS = {
    "modelscan_version": __version__,
    "supported_zip_extensions": [".zip", ".npz"],
    "scanners": {
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
            ],  # Pickle versions 0, 1, 2 have those function under '__builtin__'
            "builtins": [
                "eval",
                "compile",
                "getattr",
                "apply",
                "exec",
                "open",
                "breakpoint",
                "__import__",
            ],  # Pickle versions 3, 4 have those function under 'builtins'
            "runpy": "*",
            "os": "*",
            "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
            "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
            "socket": "*",
            "subprocess": "*",
            "sys": "*",
            "operator": [
                "attrgetter",  # Ex of code execution: operator.attrgetter("system")(__import__("os"))("echo pwned")
            ],
            "pty": "*",
            "pickle": "*",
            "bdb": "*",
            "pdb": "*",
            "shutil": "*",
            "asyncio": "*",
        },
        "HIGH": {
            "webbrowser": "*",  # Includes webbrowser.open()
            "httplib": "*",  # Includes http.client.HTTPSConnection()
            "requests.api": "*",
            "aiohttp.client": "*",
        },
        "MEDIUM": {},
        "LOW": {},
    },
    "reporting": {
        "module": "modelscan.reports.ConsoleReport",
        "settings": {},
    },  # JSON reporting can be configured by changing "module" to "modelscan.reports.JSONReport" and adding an optional "output_file" field. For custom reporting modules, change "module" to the module name and add the applicable settings fields
}


class SettingsUtils:
    @staticmethod
    def get_default_settings_as_toml() -> Any:
        toml_settings = tomlkit.dumps(DEFAULT_SETTINGS)

        # Add settings file header
        toml_settings = f"# ModelScan settings file\n\n{toml_settings}"

        return toml_settings
