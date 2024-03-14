from pathlib import Path
from typing import List, Union, Optional, IO, Generator
from modelscan.tools.utils import _is_zipfile
import zipfile


class ModelPathNotValid(ValueError):
    pass


class ModelDataEmpty(ValueError):
    pass


class ModelBadZip(ValueError):
    def __init__(self, e: zipfile.BadZipFile, source: str):
        self.source = source
        super().__init__(f"Bad Zip File: {e}")


class Model:
    _source: Path
    _data: Optional[IO[bytes]] = None

    def __init__(self, source: Union[str, Path], data: Optional[IO[bytes]] = None):
        self._source = Path(source)
        self._data = data

    @staticmethod
    def from_path(path: Path) -> "Model":
        if not Path.exists(path):
            raise ModelPathNotValid(f"Path {path} does not exist")

        return Model(path)

    def get_files(self) -> Generator["Model", None, None]:
        if Path.is_dir(self._source):
            for f in Path(self._source).rglob("*"):
                if Path.is_file(f):
                    yield Model(f)

    def get_zip_files(
        self, supported_extensions: List[str]
    ) -> Generator["Model", None, None]:
        if (
            not _is_zipfile(self._source)
            and Path(self._source).suffix not in supported_extensions
        ):
            return

        try:
            with zipfile.ZipFile(self._source, "r") as zip:
                file_names = zip.namelist()
                for file_name in file_names:
                    with zip.open(file_name, "r") as file_io:
                        yield Model(f"{self._source}:{file_name}", file_io)
        except zipfile.BadZipFile as e:
            raise ModelBadZip(e, f"{self._source}:{file_name}")

    def get_source(self) -> Path:
        return self._source

    def has_data(self) -> bool:
        return self._data is not None

    def get_data(self) -> IO[bytes]:
        if not self._data:
            raise ModelDataEmpty("Model data is empty.")

        return self._data
