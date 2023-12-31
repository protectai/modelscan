from modelscan.issues import IssueSeverity

DEFAULT_SCANNERS = [
    "modelscan.scanners.H5Scan",
    "modelscan.scanners.KerasScan",
    "modelscan.scanners.SavedModelScan",
    "modelscan.scanners.NumpyScan",
    "modelscan.scanners.PickleScan",
    "modelscan.scanners.PyTorchScan",
]

DEFAULT_SETTINGS = {
    "supported_zip_extensions": [".zip", ".npz"],
    "scanners": {
        "modelscan.scanners.H5Scan": {
            "enabled": True,
            "supported_extensions": [".h5"],
        },
        "modelscan.scanners.KerasScan": {
            "enabled": True,
            "supported_extensions": [".keras"],
        },
        "modelscan.scanners.SavedModelScan": {
            "enabled": True,
            "supported_extensions": [".pb"],
            "unsafe_tf_keras_operators": {
                "ReadFile": IssueSeverity.HIGH,
                "WriteFile": IssueSeverity.HIGH,
                "Lambda": IssueSeverity.MEDIUM,
            },
        },
        "modelscan.scanners.NumpyScan": {
            "enabled": True,
            "supported_extensions": [".npy"],
        },
        "modelscan.scanners.PickleScan": {
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
        "modelscan.scanners.PyTorchScan": {
            "enabled": True,
            "supported_extensions": [".bin", ".pt", ".pth", ".ckpt"],
        },
        "unsafe_globals": {
            "CRITICAL": {
                "__builtin__": {
                    "eval",
                    "compile",
                    "getattr",
                    "apply",
                    "exec",
                    "open",
                    "breakpoint",
                },  # Pickle versions 0, 1, 2 have those function under '__builtin__'
                "builtins": {
                    "eval",
                    "compile",
                    "getattr",
                    "apply",
                    "exec",
                    "open",
                    "breakpoint",
                },  # Pickle versions 3, 4 have those function under 'builtins'
                "runpy": "*",
                "os": "*",
                "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
                "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
                "socket": "*",
                "subprocess": "*",
                "sys": "*",
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
    },
}
