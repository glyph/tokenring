"""
On Windows, L{multiprocessing} does not allow administrative helper processes
that non-administrative helper processes connect to.
"""

# mypy can't see these because they're private; this is a gross monkey patch,
# so no surprise.

from multiprocessing.connection import (  # type:ignore[attr-defined]
    BUFSIZE,
    PipeListener,
)
from typing import TYPE_CHECKING

from win32file import FILE_FLAG_OVERLAPPED
from win32pipe import (
    CreateNamedPipe,
    FILE_FLAG_FIRST_PIPE_INSTANCE,
    NMPWAIT_WAIT_FOREVER,
    PIPE_ACCESS_DUPLEX,
    PIPE_READMODE_MESSAGE,
    PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
)
from win32security import (
    ConvertStringSecurityDescriptorToSecurityDescriptor as CSSDTSD,
    SDDL_REVISION_1,
    SECURITY_ATTRIBUTES,
)


if TYPE_CHECKING:

    class HANDLEType:
        # https://github.com/python/typeshed/pull/10032
        def Detach(self) -> None:
            ...

        def __int__(self) -> int:
            ...


def _new_handle(self: PipeListener, first: bool = False) -> object:
    """
    Replacement for internal pipe-allocation scheme in multiprocessing's
    internal PipeListener implementation which allows non-admins to connect to .
    """
    flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
    if first:
        flags |= FILE_FLAG_FIRST_PIPE_INSTANCE
    attribs = SECURITY_ATTRIBUTES()
    # Thank you David Heffernan https://stackoverflow.com/a/14500073/13564
    attribs.SECURITY_DESCRIPTOR = CSSDTSD("D:(A;OICI;GRGW;;;AU)", SDDL_REVISION_1)
    not_int = CreateNamedPipe(
        self._address,
        flags,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        BUFSIZE,
        BUFSIZE,
        NMPWAIT_WAIT_FOREVER,
        attribs,
    )
    pipe_handle_obj: HANDLEType = not_int  # type:ignore[assignment]
    pipe_handle_int = int(pipe_handle_obj)

    # pywin32 opened the handle, but it's going to be manipulated by the
    # stdlib's _win32api, so we need to convert it to an integer (which is the
    # type that the stdlib works in, much as it works with UNIX file
    # descriptors as ints).  We therefore need to *not* have pywin32 *close*
    # the handle, which is why we Detach() it; otherwise it closes when
    # `pipe_handle_obj` gets finalized.
    pipe_handle_obj.Detach()
    return pipe_handle_int


def _patch() -> None:
    """
    Execute the monkeypatch.
    """
    PipeListener._new_handle = _new_handle
