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
from modelscan.models.keras.scan import KerasScan
from modelscan.models.scan import ScanBase
from modelscan.tools.utils import _is_zipfile
from modelscan.utils import fetch_huggingface_repo_files, read_huggingface_file

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
        self.supported_zip_extensions = set([".zip", ".npz"])
        logger.debug(f"Supported model files {self.supported_extensions}")
        logger.debug(f"Supported zip model files {self.supported_zip_extensions}")

        # Output
        self._issues = Issues()
        self._errors: List[Error] = []
        self._skipped: List[str] = []
        self._scanned: List[str] = []

    def scan_path(self, path: Path) -> None:
        if path.is_dir():
            self._scan_directory(path)
        elif _is_zipfile(path) or path.suffix in self.supported_zip_extensions:
            is_keras_file = path.suffix in KerasScan.supported_extensions()
            if is_keras_file:
                self._scan_source(source=path, extension=path.suffix)
            else:
                self._scan_zip(path)
        else:
            self._scan_source(source=path, extension=path.suffix)

    def _scan_directory(self, directory_path: Path) -> None:
        for path in directory_path.rglob("*"):
            if not path.is_dir():
                self.scan_path(path)

    def scan_huggingface_model(self, repo_id: str) -> None:
        # List model files
        file_names = fetch_huggingface_repo_files(repo_id)
        if not file_names:
            logger.error(f"Hugging face repo {repo_id} didn't return any files")
            return

        for file_name in file_names:
            fq_file_name = f"{repo_id}/{file_name}"
            file_ext = os.path.splitext(file_name)[1]
            if (
                file_ext not in self.supported_extensions
                and file_ext not in self.supported_zip_extensions
            ):
                logger.debug(f"Skipping: {fq_file_name} is not supported")
                self._skipped.append(fq_file_name)
                continue

            raw_bytes = read_huggingface_file(repo_id, file_name)
            if not raw_bytes:
                logger.debug(f"Skipping: Failed to read {fq_file_name}")
                self._skipped.append(fq_file_name)
                continue

            data = io.BytesIO(raw_bytes)
            if (
                _is_zipfile(source=fq_file_name, data=data)
                or file_ext in self.supported_zip_extensions
            ):
                try:
                    self._scan_zip(source=fq_file_name, data=data)
                except:
                    logger.debug(f"Skipped: Failed to read")
            else:
                self._scan_source(source=fq_file_name, extension=file_ext, data=data)

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
                self._scanned.append(str(source))

        self._issues.add_issues(issues)
        self._errors.extend(errors)

    def _scan_zip(
        self, source: Union[str, Path], data: Optional[IO[bytes]] = None
    ) -> None:
        try:
            with zipfile.ZipFile(data or source, "r") as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    file_ext = os.path.splitext(file_name)[1]
                    with zip.open(file_name, "r") as file_io:
                        self._scan_source(
                            source=f"{source}:{file_name}",
                            extension=file_ext,
                            data=file_io,
                        )
        except zipfile.BadZipFile as e:
            logger.debug(f"Skipping zip file {source}, due to error", e, exc_info=True)
            self._skipped.append(str(source))

    @property
    def issues(self) -> Issues:
        return self._issues

    @property
    def errors(self) -> List[Error]:
        return self._errors

    @property
    def scanned(self) -> List[str]:
        return self._scanned

    @property
    def skipped(self) -> List[str]:
        return self._skipped
