import logging
import zipfile
import importlib

from modelscan.settings import DEFAULT_SETTINGS

from pathlib import Path
from typing import List, Union, Optional, IO, Dict, Any
from datetime import datetime

from modelscan.error import ModelScanError, ErrorCategories
from modelscan.skip import ModelScanSkipped, SkipCategories
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
        self._errors: List[ModelScanError] = []
        self._init_errors: List[ModelScanError] = []
        self._skipped: List[ModelScanSkipped] = []
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
                            scanner_path,
                            ErrorCategories.MODEL_SCAN,
                            f"Error importing scanner: {e}",
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
        pathlibPath = Path().cwd() if path == "." else Path(path).absolute()
        self._scan_path(Path(pathlibPath))
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
                # check if added to skipped already
                all_skipped_files = [skipped.source for skipped in self._skipped]
                if str(path) not in all_skipped_files:
                    self._skipped.append(
                        ModelScanSkipped(
                            "ModelScan",
                            SkipCategories.SCAN_NOT_SUPPORTED,
                            f"Model Scan did not scan file",
                            str(path),
                        )
                    )

        else:
            logger.error(f"Error: path {path} is not valid")
            self._errors.append(
                ModelScanError(
                    "ModelScan", ErrorCategories.PATH, "Path is not valid", str(path)
                )
            )

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
                scanned = True
                logger.info(f"Scanning {source} using {scanner.full_name()} model scan")
                if scan_results.errors:
                    self._errors.extend(scan_results.errors)
                elif scan_results.issues:
                    self._scanned.append(str(source))
                    self._issues.add_issues(scan_results.issues)

                elif scan_results.skipped:
                    self._skipped.extend(scan_results.skipped)
                else:
                    self._scanned.append(str(source))

        return scanned

    def _scan_zip(
        self, source: Union[str, Path], data: Optional[IO[bytes]] = None
    ) -> None:
        try:
            with zipfile.ZipFile(data or source, "r") as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    with zip.open(file_name, "r") as file_io:
                        scanned = self._scan_source(
                            source=f"{source}:{file_name}",
                            data=file_io,
                        )

                        if not scanned:
                            if _is_zipfile(file_name, data=file_io):
                                self._errors.append(
                                    ModelScanError(
                                        "ModelScan",
                                        ErrorCategories.NESTED_ZIP,
                                        "ModelScan does not support nested zip files.",
                                        f"{source}:{file_name}",
                                    )
                                )

                            # check if added to skipped already
                            all_skipped_files = [
                                skipped.source for skipped in self._skipped
                            ]
                            if f"{source}:{file_name}" not in all_skipped_files:
                                self._skipped.append(
                                    ModelScanSkipped(
                                        "ModelScan",
                                        SkipCategories.SCAN_NOT_SUPPORTED,
                                        f"Model Scan did not scan file",
                                        f"{source}:{file_name}",
                                    )
                                )

        except zipfile.BadZipFile as e:
            logger.debug(f"Skipping zip file {source}, due to error", e, exc_info=True)
            self._skipped.append(
                ModelScanSkipped(
                    "ModelScan",
                    SkipCategories.BAD_ZIP,
                    f"Skipping zip file due to error: {e}",
                    f"{source}:{file_name}",
                )
            )

    def _generate_results(self) -> Dict[str, Any]:
        report: Dict[str, Any] = {}

        absolute_path = Path(self._input_path).resolve()
        if Path(self._input_path).is_file():
            absolute_path = Path(absolute_path).parent

        issues_by_severity = self._issues.group_by_severity()
        total_issue_count = len(self._issues.all_issues)

        report["summary"] = {"total_issues_by_severity": {}}
        for severity in IssueSeverity:
            if severity.name in issues_by_severity:
                report["summary"]["total_issues_by_severity"][severity.name] = len(
                    issues_by_severity[severity.name]
                )
            else:
                report["summary"]["total_issues_by_severity"][severity.name] = 0

        report["summary"]["total_issues"] = total_issue_count
        report["summary"]["input_path"] = str(self._input_path)
        report["summary"]["absolute_path"] = str(absolute_path)
        report["summary"]["modelscan_version"] = __version__
        report["summary"]["timestamp"] = datetime.now().isoformat()

        report["summary"]["scanned"] = {"total_scanned": len(self._scanned)}

        if self._scanned:
            report["summary"]["scanned"]["scanned_files"] = [
                str(Path(file_name).relative_to(Path(absolute_path)))
                for file_name in self._scanned
            ]

        if self._issues.all_issues:
            report["issues"] = [
                issue.details.output_json() for issue in self._issues.all_issues
            ]

            for issue in report["issues"]:
                issue["source"] = str(
                    Path(issue["source"]).relative_to(Path(absolute_path))
                )
        else:
            report["issues"] = []

        all_errors = []
        if self._errors:
            for error in self._errors:
                error_information = {}
                error_information["category"] = str(error.category.name)
                if error.message:
                    error_information["description"] = error.message
                if error.source is not None:
                    error_information["source"] = str(
                        Path(str(error.source)).relative_to(Path(absolute_path))
                    )

                all_errors.append(error_information)

        report["errors"] = all_errors

        report["summary"]["skipped"] = {"total_skipped": len(self._skipped)}

        all_skipped_files = []
        if self._skipped:
            for skipped_file in self._skipped:
                skipped_file_information = {}
                skipped_file_information["category"] = str(skipped_file.category.name)
                skipped_file_information["description"] = str(skipped_file.message)
                skipped_file_information["source"] = str(
                    Path(skipped_file.source).relative_to(Path(absolute_path))
                )
                all_skipped_files.append(skipped_file_information)

        report["summary"]["skipped"]["skipped_files"] = all_skipped_files

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

    def generate_report(self) -> Optional[str]:
        reporting_module = self._settings["reporting"]["module"]
        report_settings = self._settings["reporting"]["settings"]

        scan_report = None
        try:
            (modulename, classname) = reporting_module.rsplit(".", 1)
            imported_module = importlib.import_module(
                name=modulename, package=classname
            )

            report_class = getattr(imported_module, classname)
            scan_report = report_class.generate(scan=self, settings=report_settings)

        except Exception as e:
            logger.error(f"Error generating report using {reporting_module}: {e}")
            self._errors.append(
                ModelScanError(
                    "ModelScan",
                    ErrorCategories.MODEL_SCAN,
                    f"Error generating report using {reporting_module}: {e}",
                )
            )

        return scan_report

    @property
    def issues(self) -> Issues:
        return self._issues

    @property
    def errors(self) -> List[ModelScanError]:
        return self._errors

    @property
    def scanned(self) -> List[str]:
        return self._scanned

    @property
    def skipped(self) -> List[ModelScanSkipped]:
        return self._skipped
