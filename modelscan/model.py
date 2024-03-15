from pathlib import Path
from typing import List, Union, Optional, IO, Generator, Dict, Any
from modelscan.tools.utils import _is_zipfile
import zipfile


class ModelPathNotValid(ValueError):
    pass


class ModelDataEmpty(ValueError):
    pass


class ModelIsDir(ValueError):
    pass


class ModelBadZip(ValueError):
    def __init__(self, e: zipfile.BadZipFile, source: str):
        self.source = source
        super().__init__(f"Bad Zip File: {e}")


class Model:
    _source: Path
    _stream: Optional[IO[bytes]]
    _source_file_used: bool
    _context: Dict[str, Any]

    def __init__(self, source: Union[str, Path], stream: Optional[IO[bytes]] = None):
        self._source = Path(source)
        self._stream = stream
        self._source_file_used = False
        self._context = {"formats": []}

    @staticmethod
    def from_path(path: Path) -> "Model":
        if not Path.exists(path):
            raise ModelPathNotValid(f"Path {path} does not exist")

        if Path.is_dir(path):
            raise ModelIsDir(f"Path {path} is a directory")

        return Model(path)

    def set_context(self, key: str, value: Any) -> None:
        self._context[key] = value

    def get_context(self, key: str) -> Any:
        return self._context.get(key)

    def open(self) -> "Model":
        if self._stream:
            return self

        self._stream = open(self._source, "rb")
        self._source_file_used = True

        return self

    def close(self) -> None:
        # Only close the stream if we opened a file (not for IO[bytes] objects passed in)
        if self._stream and self._source_file_used:
            self._stream.close()

    def __enter__(self) -> "Model":
        return self.open()

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # type: ignore
        self.close()

    def get_zip_files(
        self, supported_extensions: List[str]
    ) -> Generator["Model", None, None]:
        if (
            not _is_zipfile(self._source, data=self._stream)
            and Path(self._source).suffix not in supported_extensions
        ):
            return

        try:
            with zipfile.ZipFile(
                self._stream if self._stream else self._source, "r"
            ) as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    with zip.open(file_name, "r") as file_io:
                        yield Model(f"{self._source}:{file_name}", file_io)
        except zipfile.BadZipFile as e:
            raise ModelBadZip(e, f"{self._source}:{file_name}")

    def get_source(self) -> Path:
        return self._source

    def get_stream(self) -> IO[bytes]:
        if not self._stream:
            raise ModelDataEmpty("Model data is empty.")

        return self._stream
