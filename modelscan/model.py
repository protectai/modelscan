from pathlib import Path
from typing import Union, Optional, IO, Dict, Any


class ModelDataEmpty(ValueError):
    pass


class Model:
    _source: Path
    _stream: Optional[IO[bytes]]
    _should_close_stream: bool  # Flag to control closing of file
    _context: Dict[str, Any]

    def __init__(self, source: Union[str, Path], stream: Optional[IO[bytes]] = None):
        self._source = Path(source)
        self._stream = stream
        self._should_close_stream = stream is None  # Only close if opened
        self._context = {"formats": []}

    def set_context(self, key: str, value: Any) -> None:
        self._context[key] = value

    def get_context(self, key: str) -> Any:
        return self._context.get(key)

    def open(self) -> "Model":
        if self._stream:
            return self

        self._stream = open(self._source, "rb")
        self._should_close_stream = True

        return self

    def close(self) -> None:
        # Only close the stream if we opened a file (not for IO[bytes] objects passed in)
        if self._stream and self._should_close_stream:
            self._stream.close()
            self._stream = None  # Avoid double-closing
            self._should_close_stream = False  # Reset the flag

    def __enter__(self) -> "Model":
        return self.open()

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # type: ignore
        self.close()

    def get_source(self) -> Path:
        return self._source

    def get_stream(self, offset: int = 0) -> IO[bytes]:
        if not self._stream:
            raise ModelDataEmpty("Model data is empty.")

        self._stream.seek(offset)
        return self._stream
