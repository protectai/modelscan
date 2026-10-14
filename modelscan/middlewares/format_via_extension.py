import pickletools

from .middleware import MiddlewareBase
from modelscan.model import Model
from modelscan.settings import SupportedModelFormats
from typing import Callable, IO

# Opcodes that can legally begin a valid protocol-0/1 pickle stream. Cheap
# first-byte filter before attempting a full structural parse.
_PICKLE_FIRST_OPCODES = b"(])}NIJKLMFGSTUVXc"


def _model_stream_looks_like_pickle(model: Model) -> bool:
    """Sniff whether the model's stream holds pickle content.

    Pickle protocols 1-5 begin with the PROTO header (``\\x80`` + version
    byte); protocol 0 begins with an opcode that can start a pickle. A
    candidate is then validated with a full pickletools parse (which only
    decodes opcodes and never executes the payload) so that text or binary
    content whose first byte happens to look like an opcode is not
    misclassified.
    """
    try:
        stream: IO[bytes] = model.get_stream()
    except Exception:
        return False
    try:
        stream.seek(0)
        magic = stream.read(2)
        if not magic:
            return False
        if magic[0:1] == b"\x80":
            candidate = len(magic) == 2 and 0x01 <= magic[1] <= 0x05
        else:
            candidate = magic[0:1] in _PICKLE_FIRST_OPCODES
        if not candidate:
            return False
        stream.seek(0)
        ops = list(pickletools.genops(stream))
        return len(ops) > 0 and ops[-1][0].name == "STOP"
    except Exception:
        return False
    finally:
        # Never let the sniff itself break a scan: if the stream turns out
        # not to be rewindable after all, fail closed to "not a pickle".
        try:
            stream.seek(0)
        except Exception:
            pass


class FormatViaExtensionMiddleware(MiddlewareBase):
    def __call__(self, model: Model, call_next: Callable[[Model], None]) -> None:
        extension = model.get_source().suffix
        formats = [
            format
            for format, extensions in self._settings["formats"].items()
            if extension in extensions
        ]
        if len(formats) > 0:
            model.set_context("formats", model.get_context("formats") or [] + formats)
        elif _model_stream_looks_like_pickle(model):
            # The extension provided no format (e.g. an extensionless zip
            # entry or file): sniff the content so a pickle hiding behind a
            # missing extension is scanned instead of silently skipped. #384
            model.set_context("formats", [SupportedModelFormats.PICKLE])

        call_next(model)
