
from multiprocessing.connection import Listener

from .multi_common import address, auth_key, family
from pyuac import main_requires_admin  # type:ignore[import]
import sys


if sys.platform == 'win32':
    import win32security
    import _winapi
    from multiprocessing.connection import PipeListener, BUFSIZE

    def _new_handle(self: PipeListener, first: bool=False) -> object:
        flags = _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
        if first:
            flags |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE
        attribs = win32security.SECURITY_ATTRIBUTES()
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                "D:(A;OICI;GRGW;;;AU)",
                win32security.SDDL_REVISION_1
            )
        attribs.SECURITY_DESCRIPTOR = descriptor
        newnp = _winapi.CreateNamedPipe(
            self._address, flags,
            _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE |
            _winapi.PIPE_WAIT,
            _winapi.PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE,
            _winapi.NMPWAIT_WAIT_FOREVER,
            # _winapi.NULL,
            attribs
        )
        return newnp
    PipeListener._new_handle = _new_handle

@main_requires_admin(cmdLine=[sys.executable, '-m', 'ctap2vault.multi_server'])
def main() -> None:
    with Listener(address=address, family=family, authkey=auth_key) as listener:
        while True:
            with listener.accept() as conn:
                while True:
                    try:
                        conn.send(conn.recv().do())
                    except EOFError:
                        break


if __name__ == '__main__':
    from sys import argv
    print(argv)
    try:
        main()
    finally:
        input("hit enter to exit")
