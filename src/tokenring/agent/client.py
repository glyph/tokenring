import sys
from contextlib import contextmanager
from dataclasses import dataclass
from multiprocessing.connection import Client, Connection
from typing import Iterator

from keyring.backend import KeyringBackend

from .common import address, auth_key, family


@contextmanager
def show_waiting() -> Iterator[None]:
    print("Waiting for agent…", file=sys.stderr, end="", flush=True)
    try:
        yield
    finally:
        print("OK", file=sys.stderr, flush=True)


@dataclass
class BackgroundTokenRing(KeyringBackend):
    """
    Keyring backend that connects to a L{tokenring.local.LocalTokenRing}
    running in a dedicated helper process, for two reasons:

        1. to minimize the amount of code running in the UAC-elevated process
           until we address the issue described in L{tokenring._admin_pipe}

        2. to reduce the number of user-presence checks when repeated
           authentications are require.  Specifically, the vault itself needs a
           UP/PIN check for unlock, but then, each credential will also need a
           UP check.  With a background helper, you can unlock the vault for a
           session and only touch the key once for each credential rather than
           twice.
    """

    connection: Connection | None = None
    priority: int = 25

    try:
        connection = Client(address=address, family=family, authkey=auth_key)
    except FileNotFoundError:
        priority = 0

    def realize_connection(self) -> Connection:
        """
        Create a connection if none is present.
        """
        if self.connection is None:
            self.connection = Client(address=address, family=family, authkey=auth_key)
        return self.connection

    def multisend(self, words: list[str]) -> str | None:
        conn = self.realize_connection()
        for word in words:
            conn.send_bytes(word.encode("utf-8"))
        ok = conn.recv_bytes()
        if ok == b"y":
            return conn.recv_bytes().decode("utf-8")
        else:
            return None

    def get_password(self, servicename: str, username: str) -> str | None:
        with show_waiting():
            return self.multisend(["get", servicename, username])

    def set_password(self, servicename: str, username: str, password: str) -> None:
        with show_waiting():
            self.multisend(["set", servicename, username, password])
