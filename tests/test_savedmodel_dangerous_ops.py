"""Test that modelscan detects dangerous TF ops beyond ReadFile/WriteFile.

Verifies that filesystem enumeration (MatchingFiles), arbitrary Python
execution (PyFunc/EagerPyFunc), and file reading ops (WholeFileReader)
are flagged by the SavedModel scanner.
"""

import pytest


class TestSavedModelDangerousOps:
    """Test that unsafe_tf_operators blocklist catches dangerous ops."""

    def test_matching_files_is_blocked(self):
        from modelscan.settings import DEFAULT_SETTINGS
        ops = DEFAULT_SETTINGS["scanners"][
            "modelscan.scanners.SavedModelTensorflowOpScan"
        ]["unsafe_tf_operators"]
        assert "MatchingFiles" in ops
        assert ops["MatchingFiles"] == "HIGH"

    def test_pyfunc_is_blocked(self):
        from modelscan.settings import DEFAULT_SETTINGS
        ops = DEFAULT_SETTINGS["scanners"][
            "modelscan.scanners.SavedModelTensorflowOpScan"
        ]["unsafe_tf_operators"]
        assert "PyFunc" in ops
        assert ops["PyFunc"] == "CRITICAL"

    def test_eager_pyfunc_is_blocked(self):
        from modelscan.settings import DEFAULT_SETTINGS
        ops = DEFAULT_SETTINGS["scanners"][
            "modelscan.scanners.SavedModelTensorflowOpScan"
        ]["unsafe_tf_operators"]
        assert "EagerPyFunc" in ops
        assert ops["EagerPyFunc"] == "CRITICAL"

    def test_whole_file_reader_is_blocked(self):
        from modelscan.settings import DEFAULT_SETTINGS
        ops = DEFAULT_SETTINGS["scanners"][
            "modelscan.scanners.SavedModelTensorflowOpScan"
        ]["unsafe_tf_operators"]
        assert "WholeFileReader" in ops
        assert ops["WholeFileReader"] == "HIGH"

    def test_original_ops_still_blocked(self):
        """Ensure ReadFile and WriteFile are still present."""
        from modelscan.settings import DEFAULT_SETTINGS
        ops = DEFAULT_SETTINGS["scanners"][
            "modelscan.scanners.SavedModelTensorflowOpScan"
        ]["unsafe_tf_operators"]
        assert "ReadFile" in ops
        assert "WriteFile" in ops
