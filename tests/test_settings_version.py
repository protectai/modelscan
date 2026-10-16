from typing import Any, Dict

import tomlkit
from click.testing import CliRunner

from modelscan._version import __version__
from modelscan.settings import DEFAULT_SETTINGS, SettingsUtils


def _settings_toml(version: Any) -> str:
    """Build a minimal valid settings TOML by hand.

    (get_default_settings_as_toml() cannot serialize DEFAULT_SETTINGS
    on current main — see the note in the PR description.)
    """
    data: Dict[str, Any] = {
        "scanners": {},
        "middlewares": {},
        "reporting": {"module": "modelscan.reports.ConsoleReport", "settings": {}},
    }
    if version is not None:
        data["modelscan_version"] = version
    return tomlkit.dumps(data)


def test_settings_version_is_current() -> None:
    assert SettingsUtils.settings_version_is_current(dict(DEFAULT_SETTINGS)) is True


def test_settings_version_is_current_on_mismatch() -> None:
    settings: Dict[str, Any] = dict(DEFAULT_SETTINGS)
    settings["modelscan_version"] = "0.0.0-test-mismatch"
    assert SettingsUtils.settings_version_is_current(settings) is False


def test_settings_version_is_current_on_missing_key() -> None:
    settings = dict(DEFAULT_SETTINGS)
    settings.pop("modelscan_version", None)
    assert SettingsUtils.settings_version_is_current(settings) is False


def _write_settings_file(path: Any, version: Any) -> None:
    path.write_text(_settings_toml(version), encoding="utf-8")


def test_cli_warns_on_stale_settings_file(tmp_path: Any) -> None:
    from modelscan.cli import cli

    settings_file = tmp_path / "modelscan-settings.toml"
    _write_settings_file(settings_file, "0.0.0-test-stale")
    target = tmp_path / "nothing-to-scan.txt"
    target.write_text("hello", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", "-p", str(target), "--settings-file", str(settings_file)]
    )
    assert "may be out of date" in result.output


def test_cli_warns_on_settings_file_without_version(tmp_path: Any) -> None:
    from modelscan.cli import cli

    settings_file = tmp_path / "modelscan-settings.toml"
    _write_settings_file(settings_file, None)
    target = tmp_path / "nothing-to-scan.txt"
    target.write_text("hello", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", "-p", str(target), "--settings-file", str(settings_file)]
    )
    assert "may be out of date" in result.output


def test_cli_quiet_on_current_settings_file(tmp_path: Any) -> None:
    from modelscan.cli import cli

    settings_file = tmp_path / "modelscan-settings.toml"
    _write_settings_file(settings_file, __version__)
    target = tmp_path / "nothing-to-scan.txt"
    target.write_text("hello", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["scan", "-p", str(target), "--settings-file", str(settings_file)]
    )
    assert "may be out of date" not in result.output
