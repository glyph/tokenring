import sys
from multiprocessing.connection import Listener
from pathlib import Path

from pyuac import main_requires_admin

from . import __name__ as relative_parent
from .common import address, auth_key, family


if sys.platform == "win32":
    from ._admin_pipe import _patch

    _patch()


from ..local import LocalTokenRing

# direct USB HID access because of this bug:

# https://github.com/Yubico/python-fido2/issues/185

cmdLine = [sys.executable, "-m", relative_parent, *sys.argv[1:]]


@main_requires_admin(
    # Since we expect to run as `-m`, sys.argv looks like __file__ to Python,
    # which means pyuac gets it wrong.
    cmdLine=cmdLine,
)
def main() -> None:
    local_ring = (
        LocalTokenRing(location=Path(sys.argv[1]))
        if len(sys.argv) > 1
        else LocalTokenRing()
    )

    vault = local_ring.realize_vault()
    with Listener(address=address, family=family, authkey=auth_key) as listener:
        while True:
            with listener.accept() as conn:
                while True:
                    password = None
                    try:
                        command = conn.recv_bytes()
                    except EOFError:
                        break
                    else:
                        if command == b"get":
                            servicename = conn.recv_bytes().decode("utf-8")
                            username = conn.recv_bytes().decode("utf-8")
                            password = vault.get_password(servicename, username)
                            if password is None:
                                conn.send_bytes(b"n")
                            else:
                                conn.send_bytes(b"y")
                                conn.send_bytes(password.encode("utf-8"))
                                password = None

                        if command == b"set":
                            servicename = conn.recv_bytes().decode("utf-8")
                            username = conn.recv_bytes().decode("utf-8")
                            password = conn.recv_bytes().decode("utf-8")
                            vault.set_password(servicename, username, password)
                            password = None
                            conn.send_bytes(b"n")


if __name__ == "__main__":
    from traceback import print_exc

    try:
        main()
    except BaseException:
        print_exc()
    input("hit 'enter' to terminate process\n")
