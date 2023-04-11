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
from .vault import Vault


@dataclass
class LocalTokenRing(KeyringBackend):
    """
    Keyring backend implementation for L{Vault} that runs in-process with the
    requesting code.
    """

    vault: Vault | None = None
    location: Path = Path(data_root()) / "keyring.tokenvault"
    priority = 20

    def realize_vault(self) -> Vault:
        """
        Create or open a vault.
        """
        if self.vault is not None:
            return self.vault
        # Ensure our location exists.
        self.location.parent.mkdir(parents=True, exist_ok=True)
        # XXX gotta choose the correct client
        if self.location.is_file():
            self.vault = Vault.load(self.location)
        else:
            self.vault = Vault.create(self.location)
        return self.vault

    def get_password(self, servicename: str, username: str) -> str:
        return self.realize_vault().get_password(servicename, username)

    def set_password(self, servicename: str, username: str, password: str) -> None:
        self.realize_vault().set_password(servicename, username, password)


if TYPE_CHECKING:
    LocalTokenRing()
