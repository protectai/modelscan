import logging
import pickletools  # nosec
from tarfile import TarError
from typing import IO, Any, Dict, List, Set, Tuple, Union, Optional

import numpy as np

from modelscan.error import PickleGenopsError
from modelscan.skip import ModelScanSkipped, SkipCategories
from modelscan.issues import Issue, IssueCode, IssueSeverity, OperatorIssueDetails
from modelscan.scanners.scan import ScanResults
from modelscan.model import Model

logger = logging.getLogger("modelscan")

from .utils import MAGIC_NUMBER, _should_read_directly, get_magic_number


class GenOpsError(Exception):
    def __init__(self, msg: str, globals: Optional[Set[Tuple[str, str]]]):
        self.msg = msg
        self.globals = globals
        super().__init__()

    def __str__(self) -> str:
        return self.msg


# TODO: handle methods loading other Pickle files (either mark as suspicious, or follow calls to scan other files [preventing infinite loops])
#
# pickle.loads()
# https://docs.python.org/3/library/pickle.html#pickle.loads
# pickle.load()
# https://docs.python.org/3/library/pickle.html#pickle.load
# numpy.load()
# https://numpy.org/doc/stable/reference/generated/numpy.load.html#numpy.load
# numpy.ctypeslib.load_library()
# https://numpy.org/doc/stable/reference/routines.ctypeslib.html#numpy.ctypeslib.load_library
# pandas.read_pickle()
# https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.read_pickle.html
# joblib.load()
# https://joblib.readthedocs.io/en/latest/generated/joblib.load.html
# torch.load()
# https://pytorch.org/docs/stable/generated/torch.load.html
# tf.keras.models.load_model()
# https://www.tensorflow.org/api_docs/python/tf/keras/models/load_model
#


def _list_globals(
    data: IO[bytes], multiple_pickles: bool = True
) -> Set[Tuple[str, str]]:
    globals: Set[Any] = set()

    memo: Dict[Union[int, str], str] = {}
    # Scan the data for pickle buffers, stopping when parsing fails or stops making progress
    last_byte = b"dummy"
    while last_byte != b"":
        # List opcodes
        try:
            ops: List[Tuple[Any, Any, Union[int, None]]] = list(
                pickletools.genops(data)
            )
        except Exception as e:
            # Given we can have multiple pickles in a file, we may have already successfully extracted globals from a valid pickle.
            # Thus return the already found globals in the error & let the caller decide what to do.
            globals_opt = globals if len(globals) > 0 else None
            raise GenOpsError(str(e), globals_opt)

        last_byte = data.read(1)
        data.seek(-1, 1)

        # Extract global imports
        for n in range(len(ops)):
            op = ops[n]
            op_name = op[0].name
            op_value: str = op[1]

            if op_name == "MEMOIZE" and n > 0:
                memo[len(memo)] = ops[n - 1][1]
            elif op_name in ["PUT", "BINPUT", "LONG_BINPUT"] and n > 0:
                memo[op_value] = ops[n - 1][1]
            elif op_name in ("GLOBAL", "INST"):
                globals.add(tuple(op_value.split(" ", 1)))
            elif op_name == "STACK_GLOBAL":
                values: List[str] = []
                for offset in range(1, n):
                    if ops[n - offset][0].name in [
                        "MEMOIZE",
                        "PUT",
                        "BINPUT",
                        "LONG_BINPUT",
                    ]:
                        continue
                    if ops[n - offset][0].name in ["GET", "BINGET", "LONG_BINGET"]:
                        values.append(memo[int(ops[n - offset][1])])
                    elif ops[n - offset][0].name not in [
                        "SHORT_BINUNICODE",
                        "UNICODE",
                        "BINUNICODE",
                        "BINUNICODE8",
                    ]:
                        logger.debug(
                            "Presence of non-string opcode, categorizing as an unknown dangerous import"
                        )
                        values.append("unknown")
                    else:
                        values.append(ops[n - offset][1])
                    if len(values) == 2:
                        break
                if len(values) != 2:
                    raise ValueError(
                        f"Found {len(values)} values for STACK_GLOBAL at position {n} instead of 2."
                    )
                globals.add((values[1], values[0]))
        if not multiple_pickles:
            break

    return globals


def scan_pickle_bytes(
    model: Model,
    settings: Dict[str, Any],
    scan_name: str = "pickle",
    multiple_pickles: bool = True,
    offset: int = 0,
) -> ScanResults:
    """Disassemble a Pickle stream and report issues"""
    issues: List[Issue] = []
    try:
        raw_globals = _list_globals(model.get_stream(offset), multiple_pickles)
    except GenOpsError as e:
        if e.globals is not None:
            return _build_scan_result_from_raw_globals(
                e.globals,
                model,
                settings,
            )
        return ScanResults(
            issues,
            [
                PickleGenopsError(
                    scan_name,
                    f"Parsing error: {e}",
                    model,
                )
            ],
            [],
        )
    logger.debug("Global imports in %s: %s", model, raw_globals, settings)
    return _build_scan_result_from_raw_globals(raw_globals, model, settings)


def _build_scan_result_from_raw_globals(
    raw_globals: Set[Tuple[str, str]],
    model: Model,
    settings: Dict[str, Any],
) -> ScanResults:
    issues: List[Issue] = []
    severities = {
        "CRITICAL": IssueSeverity.CRITICAL,
        "HIGH": IssueSeverity.HIGH,
        "MEDIUM": IssueSeverity.MEDIUM,
        "LOW": IssueSeverity.LOW,
    }

    for rg in raw_globals:
        global_module, global_name, severity = rg[0], rg[1], None
        for severity_name in severities:
            if global_module not in settings["unsafe_globals"][severity_name]:
                continue
            filter = settings["unsafe_globals"][severity_name][global_module]
            if filter == "*":
                severity = severities[severity_name]
                break
            for filter_value in filter:
                if filter_value in global_name:
                    severity = severities[severity_name]
                    break
            else:
                continue
            break
        if "unknown" in global_module or "unknown" in global_name:
            severity = IssueSeverity.CRITICAL  # we must assume it is RCE
        if severity is not None:
            issues.append(
                Issue(
                    code=IssueCode.UNSAFE_OPERATOR,
                    severity=severity,
                    details=OperatorIssueDetails(
                        module=global_module,
                        operator=global_name,
                        source=model.get_source(),
                        severity=severity,
                    ),
                )
            )
    return ScanResults(issues, [], [])


def scan_numpy(model: Model, settings: Dict[str, Any]) -> ScanResults:
    scan_name = "numpy"
    # Code to distinguish from NumPy binary files and pickles.
    _ZIP_PREFIX = b"PK\x03\x04"
    _ZIP_SUFFIX = b"PK\x05\x06"  # empty zip files start with this
    N = len(np.lib.format.MAGIC_PREFIX)
    stream = model.get_stream()
    magic = stream.read(N)
    # If the file size is less than N, we need to make sure not
    # to seek past the beginning of the file
    stream.seek(-min(N, len(magic)), 1)  # back-up
    if magic.startswith(_ZIP_PREFIX) or magic.startswith(_ZIP_SUFFIX):
        # .npz file
        return ScanResults(
            [],
            [],
            [
                ModelScanSkipped(
                    scan_name,
                    SkipCategories.NOT_IMPLEMENTED,
                    "Scanning of .npz files is not implemented yet",
                    str(model.get_source()),
                )
            ],
        )

    elif magic == np.lib.format.MAGIC_PREFIX:
        # .npy file
        version = np.lib.format.read_magic(stream)  # type: ignore[no-untyped-call]
        np.lib.format._check_version(version)  # type: ignore[attr-defined]
        _, _, dtype = np.lib.format._read_array_header(stream, version)  # type: ignore[attr-defined]

        if dtype.hasobject:
            return scan_pickle_bytes(model, settings, scan_name, True, stream.tell())
        else:
            return ScanResults([], [], [])
    else:
        return scan_pickle_bytes(model, settings, scan_name)


def scan_pytorch(model: Model, settings: Dict[str, Any]) -> ScanResults:
    scan_name = "pytorch"
    should_read_directly = _should_read_directly(model.get_stream())
    if should_read_directly and model.get_stream().tell() == 0:
        # try loading from tar
        try:
            # TODO: implement loading from tar
            raise TarError()
        except TarError:
            # file does not contain a tar
            model.get_stream().seek(0)

    magic = get_magic_number(model.get_stream())
    if magic != MAGIC_NUMBER:
        return ScanResults(
            [],
            [],
            [
                ModelScanSkipped(
                    scan_name,
                    SkipCategories.MAGIC_NUMBER,
                    "Invalid magic number",
                    str(model.get_source()),
                )
            ],
        )

    return scan_pickle_bytes(model, settings, scan_name, multiple_pickles=False)
