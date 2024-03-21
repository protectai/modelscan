import abc
from modelscan.model import Model
from typing import Callable, Dict, Any, List
import importlib


class MiddlewareImportError(Exception):
    pass


class MiddlewareBase(metaclass=abc.ABCMeta):
    _settings: Dict[str, Any]

    def __init__(self, settings: Dict[str, Any]):
        self._settings = settings

    @abc.abstractmethod
    def __call__(
        self,
        model: Model,
        call_next: Callable[[Model], None],
    ) -> None:
        raise NotImplementedError


class MiddlewarePipeline:
    _middlewares: List[MiddlewareBase]

    def __init__(self) -> None:
        self._middlewares = []

    @staticmethod
    def from_settings(middleware_settings: Dict[str, Any]) -> "MiddlewarePipeline":
        pipeline = MiddlewarePipeline()

        for path, params in middleware_settings.items():
            try:
                (modulename, classname) = path.rsplit(".", 1)
                imported_module = importlib.import_module(
                    name=modulename, package=classname
                )

                middleware_class: MiddlewareBase = getattr(imported_module, classname)
                pipeline.add_middleware(middleware_class(params))  # type: ignore
            except Exception as e:
                raise MiddlewareImportError(f"Error importing middleware {path}: {e}")

        return pipeline

    def add_middleware(self, middleware: MiddlewareBase) -> "MiddlewarePipeline":
        self._middlewares.append(middleware)
        return self

    def run(self, model: Model) -> None:
        def runner(model: Model, index: int) -> None:
            if index < len(self._middlewares):
                self._middlewares[index](model, lambda model: runner(model, index + 1))

        runner(model, 0)
