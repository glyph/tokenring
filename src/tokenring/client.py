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
import ctypes

try:
    from fido2.pcsc import CtapPcscDevice

    have_pcsc = True
except ImportError:
    have_pcsc = False

if TYPE_CHECKING:
    AnyCtapDevice = CtapHidDevice | CtapPcscDevice

def enumerate_devices() -> Iterable[AnyCtapDevice]:
    yield from CtapHidDevice.list_devices()
    if have_pcsc:
        yield from CtapPcscDevice.list_devices()


class NoAuthenticator(Exception):
    """
    Could not find an authenticator.
    """

AnyFidoClient = Fido2Client | WindowsClient

fake_url = "https://hardware.keychain.glyph.im"

def enumerate_clients(
    interaction: UserInteraction,
) -> Iterable[tuple[AnyFidoClient, AnyCtapDevice | None]]:
    # Locate a device
    if WindowsClient.is_available():
        is_admin: bool = ctypes.windll.shell32.IsUserAnAdmin()  # type:ignore
        if not is_admin:
            yield (WindowsClient(fake_url), None)
            return
    for dev in enumerate_devices():
        yield (
            Fido2Client(
                dev,
                fake_url,
                user_interaction=interaction,
            ),
            dev,
        )


def extension_required(client: AnyFidoClient) -> bool:
    """
    Client filter for clients that support the hmac-secret extension.
    """
    has_extension = "hmac-secret" in client.info.extensions
    return has_extension


def select_client(
    interaction: UserInteraction,
    filters: Sequence[Callable[[AnyFidoClient], bool]],
    choose: Callable[[Sequence[tuple[AnyFidoClient, AnyCtapDevice | None]]], AnyFidoClient],
) -> AnyFidoClient:
    """
    Prompt the user to choose a device to authenticate with, if necessary.
    """
    eligible = []
    for client, device in enumerate_clients(interaction):
        if all(each(client) for each in filters):
            eligible.append((client, device))
    if not eligible:
        raise NoAuthenticator("No eligible authenticators found.")
    if len(eligible) == 1:
        return eligible[0][0]
    return choose(eligible)


