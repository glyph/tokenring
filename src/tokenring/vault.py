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

from .interaction import ConsoleInteraction
from .client import AnyFidoClient, extension_required, select_client
from .handles import CredentialHandle, KeyHandle, SerializedKeyHandle
from .interaction import console_chooser
from fido2.client import ClientError, Fido2Client, UserInteraction, WindowsClient


@dataclass
class Vault:
    """
    A vault where users may store multiple credentials.
    """

    interaction: ConsoleInteraction
    client: AnyFidoClient
    vault_handle: KeyHandle
    handles: dict[tuple[str, str], tuple[KeyHandle, str]]
    storage_path: Path

    def serialize(self) -> SerializedVault:
        """
        Serialize this vault.
        """
        return {
            "key": self.vault_handle.serialize(),
            "data": self.vault_handle.encrypt_text(
                dumps(
                    [
                        (service, user, handle.serialize(), ciphertext)
                        for (service, user), (
                            handle,
                            ciphertext,
                        ) in self.handles.items()
                    ]
                )
            ),
        }

    @classmethod
    def deserialize(
        cls,
        interaction: ConsoleInteraction,
        client: AnyFidoClient,
        obj: SerializedVault,
        where: Path,
    ) -> Vault:
        """
        Deserialize the given vault from a fido2client.
        """
        vault_handle = KeyHandle.deserialize(client, obj["key"])
        vault_handle.remember_key()
        unlocked = vault_handle.decrypt_text(obj["data"])
        handlesobj = loads(unlocked)
        self = Vault(
            interaction,
            client,
            vault_handle,
            handles={
                (service, user): (KeyHandle.deserialize(client, handleobj), ciphertext)
                for (service, user, handleobj, ciphertext) in handlesobj
            },
            storage_path=where.absolute(),
        )
        return self

    @classmethod
    def create(cls, where: Path) -> Vault:
        """
        Create a new Vault and save it in the given IO.
        """
        interaction = ConsoleInteraction()
        client = select_client(interaction, [extension_required], console_chooser)
        with interaction.purpose("create the vault"):
            cred = CredentialHandle.new_credential(client)
        vault_key = KeyHandle.new(cred)
        with interaction.purpose("open the vault we just created"):
            vault_key.remember_key()
        self = Vault(interaction, client, vault_key, {}, where.absolute())
        self.save()
        return self

    @classmethod
    def load(cls, where: Path) -> Vault:
        """
        Load an existing vault saved at a given path.
        """
        where = where.absolute()
        with where.open("r") as f:
            contents = load(f)
        interaction = ConsoleInteraction()
        while True:
            client = select_client(interaction, [extension_required], console_chooser)
            try:
                with interaction.purpose(f"open the vault at {where.as_posix()}"):
                    return cls.deserialize(interaction, client, contents, where)

            except ClientError as ce:
                if ce.code != ClientError.ERR.DEVICE_INELIGIBLE:
                    raise ce
                print("This is the wrong authenticator.  Try touching a different one.")

    def save(self) -> None:
        """
        Save the vault to secondary storage.
        """
        # Be extra-careful about atomicity; we really do not want to have a
        # partial write happen here, as we'll lose the whole vault.
        temp = (
            self.storage_path.parent
            / f".{self.storage_path.name}.{uuid4()}.atomic-temp"
        )

        serialized = self.serialize()

        with temp.open("w") as f:
            dump(serialized, f)
            f.flush()
            fsync(f.fileno())

        temp.replace(self.storage_path)

    def set_password(self, servicename: str, username: str, password: str) -> None:
        """
        Store a password for the tiven service and username.
        """
        handle = KeyHandle.new(self.vault_handle.credential)
        with self.interaction.purpose(
            f"encrypt the password for {servicename}/{username}"
        ):
            ciphertext = handle.encrypt_text(password)
        self.handles[servicename, username] = (handle, ciphertext)
        self.save()

    def get_password(self, servicename: str, username: str) -> str:
        """
        Retrieve a password.
        """
        handle, ciphertext = self.handles[servicename, username]
        with self.interaction.purpose(
            f"decrypt the password for {servicename}/{username}"
        ):
            plaintext = handle.decrypt_text(ciphertext)
        return plaintext

    def delete_password(self, servicename: str, username: str) -> None:
        """
        Delete a password.
        """
        del self.handles[servicename, username]
        self.save()


class SerializedVault(TypedDict):
    """
    Serialized form of a L{Vault}
    """

    key: SerializedKeyHandle
    data: str
