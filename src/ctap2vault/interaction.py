from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from getpass import getpass
from json import dump, dumps, load, loads
from os import fsync
from pathlib import Path
from threading import Event, Thread
from typing import (
    Callable,
    ClassVar,
    IO,
    Iterable,
    Iterator,
    List,
    NoReturn,
    Optional,
    Sequence,
    TYPE_CHECKING,
    TypedDict,
)
from uuid import uuid4

from fido2.client import ClientError, Fido2Client, UserInteraction, WindowsClient
from fido2.cose import ES256
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticatorAttestationResponse,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
)
from keyring.backend import KeyringBackend
from keyring.util.platform_ import data_root


from .client import NoAuthenticator

if TYPE_CHECKING:
    from .client import AnyCtapDevice, AnyFidoClient


class UnknownPurpose(Exception):
    """
    The authenticator requested user-presence for an unknown purpose.
    """


@dataclass
class ConsoleInteraction(UserInteraction):
    _purpose: str | None = None

    @contextmanager
    def purpose(self, description: str) -> Iterator[None]:
        """
        Temporarily set the purpose of this interaction.  Any prompts that
        occur without a purpose will raise an exception.
        """
        was, self._purpose = self._purpose, description
        try:
            yield None
        finally:
            self._purpose = was

    def prompt_up(self) -> None:
        """
        User-Presence Prompt.
        """
        if self._purpose is None:
            raise UnknownPurpose()
        print(f"Touch your authenticator to {self._purpose}")

    def request_pin(
        self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]
    ) -> str:
        """
        PIN entry required; return the PIN.
        """
        return getpass(f"Enter PIN to {self._purpose}: ")

    def request_uv(
        self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]
    ) -> bool:
        raise RuntimeError("User verification should not be required.")


def console_chooser(
    clients: Sequence[tuple[AnyFidoClient, AnyCtapDevice | None]]
) -> AnyFidoClient:
    """
    Select between different client devices we've discovered.
    """
    for idx, (client, device) in enumerate(clients):
        print(
            f"{1+idx}) {getattr(device, 'product_name')} {getattr(device, 'serial_number')} {getattr(getattr(device, 'descriptor', None), 'path', None)}"
        )

    while True:
        value = input("> ")
        try:
            result = int(value)
        except ValueError:
            print("Please enter a number.")
        else:
            try:
                return clients[result - 1][0]
            except IndexError:
                print("Please enter a number in range.")


def up_chooser(clients: Sequence[AnyFidoClient]) -> AnyFidoClient:
    """
    Choose a client from the given list of clients by prompting for user
    presence on one of them.  Does not work because of U{this bug
    <https://github.com/Yubico/python-fido2/issues/184>}.
    """
    cancel = Event()
    selected: AnyFidoClient | None = None

    def select(client: AnyFidoClient) -> None:
        nonlocal selected
        try:
            # type ignore - not available on windows, but not necessary on
            # windows
            client.selection(cancel)  # type:ignore

            selected = client
        except ClientError as e:
            if e.code != ClientError.ERR.TIMEOUT:
                raise
            else:
                return
        cancel.set()

    threads = []
    for client in clients:
        t = Thread(target=select, args=[client])
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    if selected is None:
        raise NoAuthenticator("user did not choose an authenticator")
    return selected
