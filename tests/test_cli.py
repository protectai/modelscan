# Tests for the modelscan command line interface.
from pathlib import Path

from click.testing import CliRunner

from modelscan.cli import create_settings


def test_create_settings_keeps_an_existing_file(tmp_path: Path) -> None:
    """Without --force an existing settings file is left untouched."""
    settings_path = tmp_path / "modelscan-settings.toml"
    settings_path.write_text("# custom settings\n", encoding="utf-8")

    result = CliRunner().invoke(create_settings, ["--location", str(settings_path)])

    assert result.exit_code == 0
    assert settings_path.read_text(encoding="utf-8") == "# custom settings\n"
