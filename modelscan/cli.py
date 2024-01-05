import logging
import sys
import os
from pathlib import Path
from typing import Optional
from tomlkit import parse

import click

from modelscan.modelscan import ModelScan
from modelscan.reports import ConsoleReport
from modelscan._version import __version__
from modelscan.settings import SettingsUtils, DEFAULT_SETTINGS

logger = logging.getLogger("modelscan")


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(
    "cli",
    context_settings=CONTEXT_SETTINGS,
    help="Modelscan detects machine learning model files that perform suspicious actions",
)
def cli() -> None:
    pass


@cli.command("scan", help="Scan a machine learning model file")
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
    help="Specify a settings file to use for the scan. Defaults to [PATH]/settings.toml.",
)
@click.pass_context
def scan(
        ctx: click.Context,
        log: str,
        path: Optional[str],
        show_skipped: bool,
        settings_file: Optional[str],
) -> int:
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(stream=sys.stdout))

    if log is not None:
        logger.setLevel(getattr(logging, log))

    settings_file_path = Path(
        settings_file if settings_file else f"{path}/settings.toml"
    )

    settings = DEFAULT_SETTINGS

    if settings_file_path and settings_file_path.is_file():
        with open(settings_file_path) as sf:
            settings = parse(sf.read()).unwrap()
            click.echo(f"Detected settings file. Using {settings_file_path}.")
    else:
        click.echo(
            f"No settings file detected at {settings_file_path}. Using defaults."
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
    ConsoleReport.generate(
        modelscan.issues,
        modelscan.errors,
        modelscan._skipped,
        show_skipped=show_skipped,
    )

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


@cli.command("create-settings", help="Create a modelscan settings file")
@click.option(
    "-f", "--force", is_flag=True, help="Overwrite existing settings file if it exists."
)
@click.option(
    "-l",
    "--location",
    type=click.Path(dir_okay=False, writable=True),
    help="The specific filepath to write the settings.toml file.",
)
def create_settings(force: bool, location: Optional[str]) -> None:
    working_dir = os.getcwd()
    settings_path = os.path.join(working_dir, "settings.toml")

    if location:
        settings_path = location

    try:
        open(settings_path)
        if force:
            with open(settings_path, "w") as settings_file:
                settings_file.write(SettingsUtils.get_default_settings_as_toml())
        else:
            logger.warning("settings.toml file detected. Exiting")
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
