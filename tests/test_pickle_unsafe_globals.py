import pickle
from typing import Any

from modelscan.modelscan import ModelScan


class MaliciousMailcapFindmatch:
    def __reduce__(self) -> Any:
        import mailcap

        caps = {"text/plain": [{"view": "cat %s", "test": "true"}]}
        return mailcap.findmatch, (caps, "text/plain")


def test_scan_flags_mailcap_findmatch(tmp_path) -> None:
    path = tmp_path / "mailcap.pkl"
    path.write_bytes(pickle.dumps(MaliciousMailcapFindmatch()))

    modelscan = ModelScan()
    results = modelscan.scan(path)

    assert results["summary"]["scanned"]["scanned_files"] == ["mailcap.pkl"]
    assert results["summary"]["total_issues"] == 1
    assert modelscan.issues.all_issues[0].details.module == "mailcap"
    assert modelscan.issues.all_issues[0].details.operator == "findmatch"
