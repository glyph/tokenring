
from multiprocessing.connection import Listener

from .multi_common import address, auth_key, family
from pyuac import main_requires_admin  # type:ignore[import]


@main_requires_admin
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
