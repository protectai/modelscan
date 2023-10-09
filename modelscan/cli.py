import logging
import sys
from pathlib import Path
from typing import Optional

import click

from modelscan.modelscan import Modelscan
from modelscan.reports import ConsoleReport
from modelscan._version import __version__

logger = logging.getLogger("modelscan")


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


# redefine format_usage so the appropriate command name shows up
class ModelscanCommand(click.Command):
    def format_usage(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        pieces = self.collect_usage_pieces(ctx)
        formatter.write_usage("modelscan", " ".join(pieces))


@click.command(
    context_settings=CONTEXT_SETTINGS,
    cls=ModelscanCommand,
    help="Modelscan detects machine learning model files that perform suspicious actions",
)
@click.version_option(__version__, "-v", "--version")
@click.option(
    "-p",
    "--path",
    type=click.Path(exists=True),
    default=None,
    help="Path to the file or folder to scan",
)
# @click.option(
#     "-u", "--url", type=str, default=None, help="URL to the file or folder to scan"
# )
@click.option(
    "-hf",
    "--huggingface",
    type=str,
    default=None,
    help="Name of the Hugging Face model to scan",
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
@click.pass_context
def cli(
    ctx: click.Context,
    log: str,
    # url: Optional[str],
    huggingface: Optional[str],
    path: Optional[str],
    show_skipped: bool,
) -> int:
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(stream=sys.stdout))

    if log is not None:
        logger.setLevel(getattr(logging, log))

    modelscan = Modelscan()
    if path is not None:
        pathlibPath = Path().cwd() if path == "." else Path(path).absolute()
        if not pathlibPath.exists():
            raise FileNotFoundError(f"Path {path} does not exist")
        else:
            modelscan.scan_path(pathlibPath)
    # elif url is not None:
    #     modelscan.scan_url(url)
    elif huggingface is not None:
        modelscan.scan_huggingface_model(huggingface)
    else:
        raise click.UsageError(
            "Command line must include either a path or a Hugging Face model"
        )
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
