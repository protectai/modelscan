from typing import Optional


class Error:
    def __init__(self) -> None:
        pass

    def __str__(self) -> str:
        raise NotImplementedError()


class ModelScanError(Error):
    scan_name: str
    message: Optional[str]

    def __init__(self, scan_name: str, message: Optional[str] = None) -> None:
        self.scan_name = scan_name
        self.message = message if message else "None"

    def __str__(self) -> str:
        return f"The following error was raised during a {self.scan_name} scan: \n{self.message}"
