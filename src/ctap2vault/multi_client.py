from dataclasses import dataclass
from multiprocessing.connection import Client, Connection
from typing import Callable

from keyring.backend import KeyringBackend

from .multi_common import address, auth_key, family
from ctap2vault.multi_commands import GetPassword, SetPassword


@dataclass
class BackgroundCTAP2KeyringBackend(KeyringBackend):
    """
    Connect to a process in the background which does the stuff.
    """

    connection: Connection | None = None
    priority: int = 25

    def realize_connection(self) -> Connection:
        """
        Create a connection if none is present.
        """
        if self.connection is None:
            self.connection = Client(address=address, family=family, authkey=auth_key)
        return self.connection

    def get_password(self, servicename: str, username: str) -> str:
        conn = self.realize_connection()
        conn.send(GetPassword(servicename, username))
        return conn.recv()

    def set_password(self, servicename: str, username: str, password: str) -> None:
        conn = self.realize_connection()
        conn.send(SetPassword(servicename, username, password))
        return conn.recv()
