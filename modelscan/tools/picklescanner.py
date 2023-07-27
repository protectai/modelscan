import logging
import pickletools  # nosec
from dataclasses import dataclass
from pathlib import Path
from tarfile import TarError
from typing import IO, Any, Dict, List, Set, Tuple, Union

import numpy as np

from modelscan.error import Error, ModelScanError
from modelscan.issues import Issue, IssueCode, IssueSeverity, OperatorIssueDetails

logger = logging.getLogger("modelscan")

from .utils import MAGIC_NUMBER, _should_read_directly, get_magic_number


class GenOpsError(Exception):
    def __init__(self, msg: str):
        self.msg = msg
        super().__init__()

    def __str__(self) -> str:
        return self.msg


_safe_globals: Dict[str, Set[str]] = {
    "collections": {"OrderedDict"},
    "torch": {
        "LongStorage",
        "FloatStorage",
        "HalfStorage",
        "QUInt2x4Storage",
        "QUInt4x2Storage",
        "QInt32Storage",
        "QInt8Storage",
        "QUInt8Storage",
        "ComplexFloatStorage",
        "ComplexDoubleStorage",
        "DoubleStorage",
        "BFloat16Storage",
        "BoolStorage",
        "CharStorage",
        "ShortStorage",
        "IntStorage",
        "ByteStorage",
    },
    "torch._utils": {"_rebuild_tensor_v2"},
}

_unsafe_globals: Dict[str, Any] = {
    "CRITICAL": {
        "__builtin__": {
            "eval",
            "compile",
            "getattr",
            "apply",
            "exec",
            "open",
            "breakpoint",
        },  # Pickle versions 0, 1, 2 have those function under '__builtin__'
        "builtins": {
            "eval",
            "compile",
            "getattr",
            "apply",
            "exec",
            "open",
            "breakpoint",
        },  # Pickle versions 3, 4 have those function under 'builtins'
        "runpy": "*",
        "os": "*",
        "nt": "*",  # Alias for 'os' on Windows. Includes os.system()
        "posix": "*",  # Alias for 'os' on Linux. Includes os.system()
        "socket": "*",
        "subprocess": "*",
        "sys": "*",
    },
    "HIGH": {
        "webbrowser": "*",  # Includes webbrowser.open()
        "httplib": "*",  # Includes http.client.HTTPSConnection()
        "requests.api": "*",
        "aiohttp.client": "*",
    },
    "MEDIUM": {},
    "LOW": {},
}

#
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

    memo: Dict[int, str] = {}
    # Scan the data for pickle buffers, stopping when parsing fails or stops making progress
    last_byte = b"dummy"
    while last_byte != b"":
        # List opcodes
        try:
            ops: List[Tuple[Any, Any, Union[int, None]]] = list(
                pickletools.genops(data)
            )
        except Exception as e:
            raise GenOpsError(str(e))
        last_byte = data.read(1)
        data.seek(-1, 1)

        # Extract global imports
        for n in range(len(ops)):
            op = ops[n]
            op_name = op[0].name
            op_value: str = op[1]

            if op_name == "MEMOIZE" and n > 0:
                memo[len(memo)] = ops[n - 1][1]

            if op_name == "GLOBAL":
                globals.add(tuple(op_value.split(" ", 1)))
            elif op_name == "STACK_GLOBAL":
                values: List[str] = []
                for offset in range(1, n):
                    if ops[n - offset][0].name == "MEMOIZE":
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
    data: IO[bytes],
    source: Union[Path, str],
    scan_name: str = "pickle",
    multiple_pickles: bool = True,
) -> Tuple[List[Issue], List[Error]]:
    """Disassemble a Pickle stream and report issues"""

    issues: List[Issue] = []
    try:
        raw_globals = _list_globals(data, multiple_pickles)
    except GenOpsError as e:
        return issues, [
            ModelScanError(scan_name, f"Error parsing pickle file {source}: {e}")
        ]

    logger.debug("Global imports in %s: %s", source, raw_globals)

    for rg in raw_globals:
        global_module, global_name, severity = rg[0], rg[1], None
        safe_filter = _safe_globals.get(global_module)
        unsafe_critical_filter = _unsafe_globals["CRITICAL"].get(global_module)
        unsafe_high_filter = _unsafe_globals["HIGH"].get(global_module)
        unsafe_medium_filter = _unsafe_globals["MEDIUM"].get(global_module)
        unsafe_low_filter = _unsafe_globals["LOW"].get(global_module)
        if unsafe_critical_filter is not None and (
            unsafe_critical_filter == "*" or global_name in unsafe_critical_filter
        ):
            severity = IssueSeverity.CRITICAL

        elif unsafe_high_filter is not None and (
            unsafe_high_filter == "*" or global_name in unsafe_high_filter
        ):
            severity = IssueSeverity.HIGH
        elif unsafe_medium_filter is not None and (
            unsafe_medium_filter == "*" or global_name in unsafe_medium_filter
        ):
            severity = IssueSeverity.MEDIUM
        elif unsafe_low_filter is not None and (
            unsafe_low_filter == "*" or global_name in unsafe_low_filter
        ):
            severity = IssueSeverity.LOW
        elif "unknown" in global_module or "unknown" in global_name:
            severity = IssueSeverity.MEDIUM
        elif (
            unsafe_critical_filter is None
            and unsafe_high_filter is None
            and safe_filter is None
        ):
            severity = IssueSeverity.MEDIUM
        else:
            continue
        issues.append(
            Issue(
                code=IssueCode.UNSAFE_OPERATOR,
                severity=severity,
                details=OperatorIssueDetails(
                    module=global_module, operator=global_name, source=source
                ),
            )
        )
    return issues, []


def scan_numpy(
    data: IO[bytes], source: Union[str, Path]
) -> Tuple[List[Issue], List[Error]]:
    # Code to distinguish from NumPy binary files and pickles.
    _ZIP_PREFIX = b"PK\x03\x04"
    _ZIP_SUFFIX = b"PK\x05\x06"  # empty zip files start with this
    N = len(np.lib.format.MAGIC_PREFIX)
    magic = data.read(N)
    # If the file size is less than N, we need to make sure not
    # to seek past the beginning of the file
    data.seek(-min(N, len(magic)), 1)  # back-up
    if magic.startswith(_ZIP_PREFIX) or magic.startswith(_ZIP_SUFFIX):
        # .npz file
        raise NotImplementedError("Scanning of .npz files is not implemented yet")
    elif magic == np.lib.format.MAGIC_PREFIX:
        # .npy file
        version = np.lib.format.read_magic(data)  # type: ignore[no-untyped-call]
        np.lib.format._check_version(version)  # type: ignore[attr-defined]
        _, _, dtype = np.lib.format._read_array_header(data, version)  # type: ignore[attr-defined]

        if dtype.hasobject:
            return scan_pickle_bytes(data, source, "numpy")
        else:
            return [], []
    else:
        return scan_pickle_bytes(data, source, "numpy")


def scan_pytorch(
    data: IO[bytes], source: Union[str, Path]
) -> Tuple[List[Issue], List[Error]]:
    should_read_directly = _should_read_directly(data)
    if should_read_directly and data.tell() == 0:
        # try loading from tar
        try:
            # TODO: implement loading from tar
            raise TarError()
        except TarError:
            # file does not contain a tar
            data.seek(0)

    magic = get_magic_number(data)
    if magic != MAGIC_NUMBER:
        return [], [
            ModelScanError("pytorch", f"Invalid magic number for file {source}")
        ]
    return scan_pickle_bytes(data, source, "pytorch", multiple_pickles=False)
