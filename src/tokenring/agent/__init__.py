from multiprocessing.connection import Listener

from .common import address, auth_key, family
from pyuac import main_requires_admin  # type:ignore[import]
import sys
from importlib import import_module

from . import __name__ as relative_parent

if sys.platform == "win32":
    from ._admin_pipe import _patch
    _patch()


# Elevated permissions are currently required for the helper process to have
# direct USB HID access because of this bug:

# https://github.com/Yubico/python-fido2/issues/185

@main_requires_admin(
    # Since we expect to run as `-m`, sys.argv looks like __file__ to Python,
    # which means pyuac gets it wrong.
    cmdLine=[sys.executable, "-m", f"{relative_parent}.agent"]
)
def main() -> None:
    with Listener(address=address, family=family, authkey=auth_key) as listener:
        while True:
            with listener.accept() as conn:
                while True:
                    try:
                        conn.send(conn.recv().do())
                    except EOFError:
                        break


if __name__ == "__main__":
    from sys import argv
    from traceback import print_exc
    try:
        main()
    except BaseException:
        print_exc()
        input("hit 'enter' to terminate process\n")
