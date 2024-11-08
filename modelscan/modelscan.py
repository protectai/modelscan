import logging
import importlib

from modelscan.settings import DEFAULT_SETTINGS

from pathlib import Path
from typing import List, Union, Dict, Any, Optional, Generator
from datetime import datetime
import zipfile

from modelscan.error import (
    ModelScanError,
    PathError,
    ErrorBase,
    ModelScanScannerError,
    NestedZipError,
)
from modelscan.skip import ModelScanSkipped, SkipCategories
from modelscan.issues import Issues, IssueSeverity
from modelscan.scanners.scan import ScanBase
from modelscan._version import __version__
from modelscan.tools.utils import _is_zipfile
from modelscan.model import Model
from modelscan.middlewares.middleware import MiddlewarePipeline, MiddlewareImportError

logger = logging.getLogger("modelscan")


class ModelScan:
    def __init__(
        self,
        settings: Dict[str, Any] = DEFAULT_SETTINGS,
    ) -> None:
        # Output
        self._issues = Issues()
        self._errors: List[ErrorBase] = []
        self._init_errors: List[ModelScanError] = []
        self._skipped: List[ModelScanSkipped] = []
        self._scanned: List[str] = []
        self._input_path: str = ""

        # Scanners
        self._scanners_to_run: List[ScanBase] = []
        self._settings: Dict[str, Any] = settings
        self._load_scanners()
        self._load_middlewares()

    def _load_middlewares(self) -> None:
        try:
            self._middleware_pipeline = MiddlewarePipeline.from_settings(
                self._settings["middlewares"] or {}
            )
        except MiddlewareImportError as e:
            logger.exception(e)
            self._init_errors.append(ModelScanError(f"Error loading middlewares: {e}"))

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
                    logger.error("Error importing scanner %s", scanner_path)
                    self._init_errors.append(
                        ModelScanError(
                            f"Error importing scanner {scanner_path}: {e}",
                        )
                    )

    def _iterate_models(self, model_path: Path) -> Generator[Model, None, None]:
        if not model_path.exists():
            logger.error("Path %s does not exist", model_path)
            self._errors.append(PathError("Path is not valid", model_path))

        files = [model_path]
        if model_path.is_dir():
            logger.debug("Path %s is a directory", str(model_path))
            files = [f for f in model_path.rglob("*") if Path.is_file(f)]

        for file in files:
            with Model(file) as model:
                yield model

                if not _is_zipfile(file, model.get_stream()):
                    continue

                try:
                    with zipfile.ZipFile(model.get_stream(), "r") as zip:
                        file_names = zip.namelist()
                        for file_name in file_names:
                            with zip.open(file_name, "r") as file_io:
                                file_name = f"{model.get_source()}:{file_name}"
                                if _is_zipfile(file_name, data=file_io):
                                    self._errors.append(
                                        NestedZipError(
                                            "ModelScan does not support nested zip files.",
                                            Path(file_name),
                                        )
                                    )
                                    continue

                                yield Model(file_name, file_io)
                except (zipfile.BadZipFile, RuntimeError) as e:
                    logger.debug(
                        "Skipping zip file %s, due to error",
                        str(model.get_source()),
                        exc_info=True,
                    )
                    self._skipped.append(
                        ModelScanSkipped(
                            "ModelScan",
                            SkipCategories.BAD_ZIP,
                            f"Skipping zip file due to error: {e}",
                            str(model.get_source()),
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
        pathlib_path = Path().cwd() if path == "." else Path(path).absolute()
        model_path = Path(pathlib_path)

        all_paths: List[Path] = []
        for model in self._iterate_models(model_path):
            self._middleware_pipeline.run(model)
            self._scan_source(model)
            all_paths.append(model.get_source())

        if self._skipped:
            all_skipped_paths = [skipped.source for skipped in self._skipped]
            for path in all_paths:
                main_file_path = str(path).split(":")[0]

                if main_file_path == str(path):
                    continue

                # If main container is skipped, we only add its content to skipped but not the file itself
                if main_file_path in all_skipped_paths:
                    self._skipped = [
                        item for item in self._skipped if item.source != main_file_path
                    ]

                    continue

        return self._generate_results()

    def _scan_source(
        self,
        model: Model,
    ) -> bool:
        scanned = False
        for scan_class in self._scanners_to_run:
            scanner = scan_class(self._settings)  # type: ignore[operator]

            try:
                scan_results = scanner.scan(model)
            except Exception as e:
                logger.error(
                    "Error encountered from scanner %s with path %s: %s",
                    scanner.full_name(),
                    str(model.get_source()),
                    e,
                )
                self._errors.append(
                    ModelScanScannerError(
                        scanner.full_name(),
                        str(e),
                        model,
                    )
                )
                continue

            if scan_results is not None:
                scanned = True
                logger.info(
                    "Scanning %s using %s model scan",
                    model.get_source(),
                    scanner.full_name(),
                )
                if scan_results.errors:
                    self._errors.extend(scan_results.errors)
                elif scan_results.issues:
                    self._scanned.append(str(model.get_source()))
                    self._issues.add_issues(scan_results.issues)

                elif scan_results.skipped:
                    self._skipped.extend(scan_results.skipped)
                else:
                    self._scanned.append(str(model.get_source()))

        if not scanned:
            all_skipped_files = [skipped.source for skipped in self._skipped]
            if str(model.get_source()) not in all_skipped_files:
                self._skipped.append(
                    ModelScanSkipped(
                        "ModelScan",
                        SkipCategories.SCAN_NOT_SUPPORTED,
                        "Model Scan did not scan file",
                        str(model.get_source()),
                    )
                )

        return scanned

    def _generate_results(self) -> Dict[str, Any]:
        report: Dict[str, Any] = {}

        absolute_path = Path(self._input_path).absolute()
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
            scanned_files = []
            for file_name in self._scanned:
                scanned_files.append(
                    str(Path(file_name).relative_to(Path(absolute_path)))
                )

            report["summary"]["scanned"]["scanned_files"] = scanned_files

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
                error_information = error.to_dict()
                if "source" in error_information:
                    error_information["source"] = str(
                        Path(error_information["source"]).relative_to(
                            Path(absolute_path)
                        )
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
            logger.error("Error generating report using %s: %s", reporting_module, e)
            self._errors.append(
                ModelScanError(f"Error generating report using {reporting_module}: {e}")
            )

        return scan_report

    @property
    def issues(self) -> Issues:
        return self._issues

    @property
    def errors(self) -> List[ErrorBase]:
        return self._errors

    @property
    def scanned(self) -> List[str]:
        return self._scanned

    @property
    def skipped(self) -> List[ModelScanSkipped]:
        return self._skipped
