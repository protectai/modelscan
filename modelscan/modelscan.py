import logging
import importlib

from modelscan.settings import DEFAULT_SETTINGS

from pathlib import Path
from typing import List, Union, Dict, Any
from datetime import datetime

from modelscan.error import ModelScanError, ErrorCategories
from modelscan.skip import ModelScanSkipped, SkipCategories
from modelscan.issues import Issues, IssueSeverity
from modelscan.scanners.scan import ScanBase
from modelscan._version import __version__
from modelscan.tools.utils import _is_zipfile
from modelscan.model import Model, ModelPathNotValid, ModelBadZip

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

        try:
            model = Model.from_path(Path(pathlibPath))
            self._scan_model(model)
        except ModelPathNotValid as e:
            logger.exception(e)
            self._errors.append(
                ModelScanError(
                    "ModelScan", ErrorCategories.PATH, "Path is not valid", str(path)
                )
            )

        return self._generate_results()

    def _scan_model(
        self,
        model: Model,
    ) -> None:
        scanned = self._scan_source(model)

        has_extracted = False
        if not scanned:
            extracted_models = model.get_files()
            for extracted_model in extracted_models:
                has_extracted = True
                self._scan_model(extracted_model)

            if has_extracted:
                return

        try:
            extracted_models = model.get_zip_files(
                self._settings["supported_zip_extensions"]
            )
        except ModelBadZip as e:
            logger.debug(
                f"Skipping zip file {str(model.get_source())}, due to error",
                e,
                exc_info=True,
            )
            self._skipped.append(
                ModelScanSkipped(
                    "ModelScan",
                    SkipCategories.BAD_ZIP,
                    f"Skipping zip file due to error: {e}",
                    e.source,
                )
            )
            return

        has_extracted = False
        for extracted_model in extracted_models:
            has_extracted = True
            scanned = self._scan_source(extracted_model)
            if not scanned:
                if _is_zipfile(
                    extracted_model.get_source(),
                    data=extracted_model.get_data()
                    if extracted_model.has_data()
                    else None,
                ):
                    self._errors.append(
                        ModelScanError(
                            "ModelScan",
                            ErrorCategories.NESTED_ZIP,
                            "ModelScan does not support nested zip files.",
                            str(extracted_model.get_source()),
                        )
                    )

                # check if added to skipped already
                all_skipped_files = [skipped.source for skipped in self._skipped]
                if str(extracted_model.get_source()) not in all_skipped_files:
                    self._skipped.append(
                        ModelScanSkipped(
                            "ModelScan",
                            SkipCategories.SCAN_NOT_SUPPORTED,
                            f"Model Scan did not scan file",
                            str(extracted_model.get_source()),
                        )
                    )

        if not scanned and not has_extracted:
            # check if added to skipped already
            all_skipped_files = [skipped.source for skipped in self._skipped]
            if str(model.get_source()) not in all_skipped_files:
                self._skipped.append(
                    ModelScanSkipped(
                        "ModelScan",
                        SkipCategories.SCAN_NOT_SUPPORTED,
                        f"Model Scan did not scan file",
                        str(model.get_source()),
                    )
                )

    def _scan_source(
        self,
        model: Model,
    ) -> bool:
        scanned = False
        for scan_class in self._scanners_to_run:
            scanner = scan_class(self._settings)  # type: ignore[operator]
            scan_results = scanner.scan(model)

            if scan_results is not None:
                scanned = True
                logger.info(
                    f"Scanning {model.get_source()} using {scanner.full_name()} model scan"
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

        return scanned

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
            scanned_files = []
            for file_name in self._scanned:
                resolved_file = Path(file_name).resolve()
                scanned_files.append(
                    str(resolved_file.relative_to(Path(absolute_path)))
                )

            report["summary"]["scanned"]["scanned_files"] = scanned_files

        if self._issues.all_issues:
            report["issues"] = [
                issue.details.output_json() for issue in self._issues.all_issues
            ]

            for issue in report["issues"]:
                resolved_file = Path(issue["source"]).resolve()
                issue["source"] = str(resolved_file.relative_to(Path(absolute_path)))
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
                    resolved_file = Path(error.source).resolve()
                    error_information["source"] = str(
                        resolved_file.relative_to(Path(absolute_path))
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
                resolved_file = Path(skipped_file.source).resolve()
                skipped_file_information["source"] = str(
                    resolved_file.relative_to(Path(absolute_path))
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
