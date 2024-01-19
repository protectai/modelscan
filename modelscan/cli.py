import logging
import sys
import os
import importlib
from pathlib import Path
from typing import Optional, Dict, Any
from tomlkit import parse

import click

from modelscan.modelscan import ModelScan
from modelscan.reports import Report
from modelscan._version import __version__
from modelscan.settings import (
    SettingsUtils,
    DEFAULT_SETTINGS,
    DEFAULT_REPORTING_MODULES,
)
from modelscan.tools.cli_utils import DefaultGroup

logger = logging.getLogger("modelscan")


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(
    "cli",
    cls=DefaultGroup,
    default="scan",
    context_settings=CONTEXT_SETTINGS,
    help="""
    Modelscan detects machine learning model files that perform suspicious actions.
    
    To scan a model file or directory, simply point toward your desired path:
    `modelscan -p /path/to/model_file.h5` 
    
    Scanning is the default action. If you'd like more information on configurations run:
    `modelscan scan --help`
    
    You can also create a configurable settings file using:
    `modelscan create-settings-file`
    
    """,
    default_if_no_args=True,
)
def cli() -> None:
    pass


@click.version_option(__version__, "-v", "--version")
@click.option(
    "-p",
    "--path",
    type=click.Path(exists=True),
    default=None,
    help="Path to the file or folder to scan",
)
@click.option(
    "-l",
    "--log",
    type=click.Choice(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]),
    default="INFO",
    help="level of log messages to display (default: INFO)",
)
@click.option(
    "--show-skipped",
    is_flag=True,
    default=False,
    help="Print a list of files that were skipped during the scan",
)
@click.option(
    "--settings-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Specify a settings file to use for the scan. Defaults to ./modelscan-settings.toml.",
)
@click.option(
    "-r",
    "--reporting-format",
    type=click.Choice(["console", "json", "custom"]),
    default="console",
    help="Format of the output. Options are console, json, or custom (to be defined in settings-file). Default is console.",
)
@click.option(
    "-o",
    "--output-file",
    type=click.Path(),
    default=None,
    help="Optional file name for output report",
)
@cli.command(
    help="[Default] Scan a model file or diretory for ability to execute suspicious actions. "
)  # type: ignore
@click.pass_context
def scan(
    ctx: click.Context,
    log: str,
    path: Optional[str],
    show_skipped: bool,
    settings_file: Optional[str],
    reporting_format: str,
    output_file: Path,
) -> int:
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(stream=sys.stdout))

    if log is not None:
        logger.setLevel(getattr(logging, log))

    settings_file_path = Path(
        settings_file if settings_file else f"{os.getcwd()}/modelscan-settings.toml"
    )

    settings = DEFAULT_SETTINGS

    if settings_file_path and settings_file_path.is_file():
        with open(settings_file_path) as sf:
            settings = parse(sf.read()).unwrap()
            click.echo(f"Detected settings file. Using {settings_file_path}. \n")
    else:
        click.echo(
            f"No settings file detected at {settings_file_path}. Using defaults. \n"
        )

    modelscan = ModelScan(settings=settings)

    if path is not None:
        pathlibPath = Path().cwd() if path == "." else Path(path).absolute()
        if not pathlibPath.exists():
            raise FileNotFoundError(f"Path {path} does not exist")
        else:
            modelscan.scan(pathlibPath)
    else:
        raise click.UsageError("Command line must include a path")

    report_settings: Dict[str, Any] = {}
    if reporting_format == "custom":
        reporting_module = settings["reporting"]["module"]  # type: ignore[index]
    else:
        reporting_module = DEFAULT_REPORTING_MODULES[reporting_format]

    report_settings = settings["reporting"]["settings"]  # type: ignore[index]
    report_settings["show_skipped"] = show_skipped
    report_settings["output_file"] = output_file

    try:
        (modulename, classname) = reporting_module.rsplit(".", 1)
        imported_module = importlib.import_module(name=modulename, package=classname)

        report_class: Report = getattr(imported_module, classname)
        report_class.generate(scan=modelscan, settings=report_settings)

    except Exception as e:
        logger.error(f"Error generating report using {reporting_module}: {e}")

    # exit code 3 if no supported files were passed
    if not modelscan.scanned:
        return 3
    # exit code 2 if scan encountered errors
    elif modelscan.errors:
        return 2
    # exit code 1 if scan completed successfully and vulnerabilities were found
    elif modelscan.issues.all_issues:
        return 1
    # exit code 0 if scan completed successfully and no vulnerabilities were found
    else:
        return 0


@cli.command("create-settings-file", help="Create a modelscan settings file")  # type: ignore
@click.option(
    "-f", "--force", is_flag=True, help="Overwrite existing settings file if it exists."
)
@click.option(
    "-l",
    "--location",
    type=click.Path(dir_okay=False, writable=True),
    help="The specific filepath to write the settings file.",
)
def create_settings(force: bool, location: Optional[str]) -> None:
    working_dir = os.getcwd()
    settings_path = os.path.join(working_dir, "modelscan-settings.toml")

    if location:
        settings_path = location

    try:
        open(settings_path)
        if force:
            with open(settings_path, "w") as settings_file:
                settings_file.write(SettingsUtils.get_default_settings_as_toml())
        else:
            logger.warning(
                f"{settings_path} file already exists. Please use `--force` flag if you intend to overwrite it."
            )
    except FileNotFoundError:
        with open(settings_path, "w") as settings_file:
            settings_file.write(SettingsUtils.get_default_settings_as_toml())


def main() -> None:
    try:
        result = cli.main(standalone_mode=False)

    except click.ClickException as e:
        click.echo(f"Error: {e}")
        with click.Context(cli) as ctx:
            click.echo(cli.get_help(ctx))
        # exit code 4 for CLI usage errors
        result = 4

    except Exception as e:
        click.echo(f"Exception: {e}")
        # exit code 2 if scan throws exceptions
        result = 2

    finally:
        sys.exit(result)


if __name__ == "__main__":
    main()
