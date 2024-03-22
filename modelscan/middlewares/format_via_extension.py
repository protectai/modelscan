from .middleware import MiddlewareBase
from modelscan.model import Model
from typing import Callable


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

        call_next(model)
