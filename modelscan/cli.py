import logging
import sys
from pathlib import Path
from typing import Optional

import click

from modelscan.modelscan import Modelscan
from modelscan.reports import ConsoleReport

logger = logging.getLogger("modelscan")


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.command(
    context_settings=CONTEXT_SETTINGS,
    help="Modelscan detects machine learning model files that perform suspicious actions",
)
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

    try:
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
        return 0

    except click.UsageError as e:
        click.echo(e)
        click.echo(ctx.get_help())
        return 2

    except Exception as e:
        logger.exception(f"Exception: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(cli())
