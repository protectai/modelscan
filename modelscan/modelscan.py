import io
import json
import logging
import os
import zipfile
import inspect

from pathlib import Path
from typing import List, Union, Optional, IO

from modelscan.error import Error
from modelscan.issues import Issues, Issue
from modelscan import models
from modelscan.models.scan import ScanBase
from modelscan.tools.utils import _http_get, _is_zipfile

logger = logging.getLogger("modelscan")


class Modelscan:
    def __init__(self) -> None:
        # Scans

        self.supported_model_scans = [
            member
            for _, member in inspect.getmembers(models)
            if inspect.isclass(member)
            and issubclass(member, ScanBase)
            and not inspect.isabstract(member)
        ]
        self.supported_extensions = set()
        for scan in self.supported_model_scans:
            self.supported_extensions.update(scan.supported_extensions())

        logger.debug(f"Supported model files {self.supported_extensions}")

        # Output
        self._issues = Issues()
        self._errors: List[Error] = []
        self._skipped: List[str] = []

    def scan_path(self, path: Path) -> None:
        if path.is_dir():
            self._scan_directory(path)
        elif _is_zipfile(path) or path.suffix in self._supported_zip_extensions():
            self._scan_zip(path)
        else:
            self._scan_source(source=path, extension=path.suffix)

    def _scan_directory(self, directory_path: Path) -> None:
        for path in directory_path.rglob("*"):
            if not path.is_dir():
                self.scan_path(path)

    def scan_huggingface_model(self, repo_id: str) -> None:
        # List model files
        model = json.loads(
            _http_get(f"https://huggingface.co/api/models/{repo_id}").decode("utf-8")
        )
        file_names = [
            file_name
            for file_name in (sibling.get("rfilename") for sibling in model["siblings"])
            if file_name is not None
        ]

        # Scan model files
        for file_name in file_names:
            file_ext = os.path.splitext(file_name)[1]
            url = f"https://huggingface.co/{repo_id}/resolve/main/{file_name}"
            self._scan_source(
                source=url,
                extension=file_ext,
                data=io.BytesIO(_http_get(url)),
            )

    def scan_url(self, url: str) -> None:
        # Todo: before it was just scanning scanning_pickle_bytes
        # We need to validate this url and determine what type of file it is
        # self._scan_bytes(
        #     data=io.BytesIO(_http_get(url)),
        #     source=url,
        #     extension=file_ext,
        # )
        pass

    def _scan_source(
        self,
        source: Union[str, Path],
        extension: str,
        data: Optional[IO[bytes]] = None,
    ) -> None:
        issues: List[Issue] = []
        errors: List[Error] = []

        if extension not in self.supported_extensions:
            logger.debug(f"Skipping file {source}")
            self._skipped.append(str(source))
            return

        for scan in self.supported_model_scans:
            if extension in scan.supported_extensions():
                logger.info(f"Scanning {source} using {scan.name()} model scan")
                issues, errors = scan.scan(source=source, data=data)

        self._issues.add_issues(issues)
        self._errors.extend(errors)

    def _scan_zip(self, source: Union[str, Path]) -> None:
        with zipfile.ZipFile(source, "r") as zip:
            file_names = zip.namelist()
            for file_name in file_names:
                file_ext = os.path.splitext(file_name)[1]
                with zip.open(file_name, "r") as file_io:
                    self._scan_source(
                        source=f"{source}:{file_name}",
                        extension=file_ext,
                        data=file_io,
                    )

    @staticmethod
    def _supported_zip_extensions() -> List[str]:
        return [".zip", ".npz"]

    @property
    def issues(self) -> Issues:
        return self._issues

    @property
    def errors(self) -> List[Error]:
        return self._errors
