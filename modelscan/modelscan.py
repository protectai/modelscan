import logging
import zipfile
import importlib

from modelscan.settings import DEFAULT_SETTINGS

from pathlib import Path
from typing import List, Union, Optional, IO, Dict, Tuple, Any
from datetime import datetime

from modelscan.error import Error, ModelScanError
from modelscan.issues import Issues, IssueSeverity
from modelscan.scanners.scan import ScanBase
from modelscan.tools.utils import _is_zipfile
from modelscan._version import __version__

logger = logging.getLogger("modelscan")


class ModelScan:
    def __init__(
        self,
        settings: Dict[str, Any] = DEFAULT_SETTINGS,
    ) -> None:
        # Output
        self._issues = Issues()
        self._errors: List[Error] = []
        self._init_errors: List[Error] = []
        self._skipped: List[str] = []
        self._scanned: List[str] = []
        self._input_path: str = ""

        # Scanners
        self._scanners_to_run: List[ScanBase] = []
        self._settings: Dict[str, Any] = settings
        self._load_scanners()

    def _load_scanners(self) -> None:
        for scanner_path, scanner_settings in self._settings["scanners"].items():
            if (
                "enabled" in scanner_settings.keys()
                and self._settings["scanners"][scanner_path]["enabled"]
            ):
                try:
                    (modulename, classname) = scanner_path.rsplit(".", 1)
                    imported_module = importlib.import_module(
                        name=modulename, package=classname
                    )

                    scanner_class: ScanBase = getattr(imported_module, classname)
                    self._scanners_to_run.append(scanner_class)

                except Exception as e:
                    logger.error(f"Error importing scanner {scanner_path}")
                    self._init_errors.append(
                        ModelScanError(
                            scanner_path, f"Error importing scanner {scanner_path}: {e}"
                        )
                    )

    def scan(
        self,
        path: Union[str, Path],
    ) -> Dict[str, Any]:
        self._issues = Issues()
        self._errors = []
        self._errors.extend(self._init_errors)
        self._skipped = []
        self._scanned = []
        self._input_path = str(path)

        self._scan_path(Path(path))
        return self._generate_results()

    def _scan_path(
        self,
        path: Path,
    ) -> None:
        if Path.exists(path):
            scanned = self._scan_source(path)
            if not scanned and path.is_dir():
                self._scan_directory(path)
            elif (
                _is_zipfile(path)
                or path.suffix in self._settings["supported_zip_extensions"]
            ):
                self._scan_zip(path)
            elif not scanned:
                self._skipped.append(str(path))
        else:
            logger.error(f"Error: path {path} is not valid")
            self._errors.append(
                ModelScanError("ModelScan", f"Path {path} is not valid")
            )
            self._skipped.append(str(path))

    def _scan_directory(self, directory_path: Path) -> None:
        for path in directory_path.rglob("*"):
            if not path.is_dir():
                self._scan_path(path)

    def _scan_source(
        self,
        source: Union[str, Path],
        data: Optional[IO[bytes]] = None,
    ) -> bool:
        scanned = False
        for scan_class in self._scanners_to_run:
            scanner = scan_class(self._settings)  # type: ignore[operator]
            scan_results = scanner.scan(
                source=source,
                data=data,
            )
            if scan_results is not None:
                logger.info(f"Scanning {source} using {scanner.full_name()} model scan")
                self._scanned.append(str(source))
                self._issues.add_issues(scan_results.issues)
                self._errors.extend(scan_results.errors)
                scanned = True
        return scanned

    def _scan_zip(
        self, source: Union[str, Path], data: Optional[IO[bytes]] = None
    ) -> None:
        try:
            with zipfile.ZipFile(data or source, "r") as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    with zip.open(file_name, "r") as file_io:
                        self._scan_source(
                            source=f"{source}:{file_name}",
                            data=file_io,
                        )
        except zipfile.BadZipFile as e:
            logger.debug(f"Skipping zip file {source}, due to error", e, exc_info=True)
            self._skipped.append(str(source))

    def _generate_results(self) -> Dict[str, Any]:
        report: Dict[str, Any] = {}

        issues_by_severity = self._issues.group_by_severity()
        total_issue_count = len(self._issues.all_issues)

        report["modelscan_version"] = __version__
        report["timestamp"] = datetime.now().isoformat()
        report["input_path"] = self._input_path
        report["total_issues"] = total_issue_count
        report["summary"] = {"total_issues_by_severity": {}}
        for severity in IssueSeverity:
            if severity.name in issues_by_severity:
                report["summary"]["total_issues_by_severity"][severity.name] = len(
                    issues_by_severity[severity.name]
                )
            else:
                report["summary"]["total_issues_by_severity"][severity.name] = 0

        report["issues_by_severity"] = {}
        for issue_key in issues_by_severity.keys():
            report["issues_by_severity"][issue_key] = [
                issue.details.output_json() for issue in issues_by_severity[issue_key]
            ]

        report["errors"] = [str(error) for index, error in enumerate(self._errors)]

        report["scanned"] = {"total_scanned": len(self._scanned)}
        report["scanned"]["scanned_files"] = [
            str(file_name) for file_name in self._scanned
        ]

        report["skipped"] = {"total_skipped": len(self._skipped)}
        report["skipped"]["skipped_files"] = [
            str(file_name) for file_name in self._skipped
        ]

        return report

    def is_compatible(self, path: str) -> bool:
        # Determines whether a file path is compatible with any of the available scanners
        if Path(path).suffix in self._settings["supported_zip_extensions"]:
            return True
        for scanner_path, scanner_settings in self._settings["scanners"].items():
            if (
                "supported_extensions" in scanner_settings.keys()
                and Path(path).suffix
                in self._settings["scanners"][scanner_path]["supported_extensions"]
            ):
                return True

        return False

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
