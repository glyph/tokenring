from __future__ import annotations

import sys
from dataclasses import dataclass
from json import dump, dumps, load, loads
from os import fsync
from pathlib import Path
from typing import (
    TypedDict,
)
from uuid import uuid4


from .interaction import ConsoleInteraction
from .fidoclient import AnyFidoClient, extension_required, select_client
from .handles import CredentialHandle, KeyHandle, SerializedKeyHandle
from .interaction import console_chooser
from fido2.client import ClientError


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
        with interaction.purpose("create the vault", "vault created!"):
            cred = CredentialHandle.new_credential(client)
        vault_key = KeyHandle.new(cred)
        with interaction.purpose("open the vault we just created", "vault open!"):
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
            dispath = where.as_posix()
            homepath = Path.home().as_posix() + "/"
            if dispath.startswith(homepath):
                dispath = "~/" + dispath[len(homepath):]
            try:
                with interaction.purpose(
                    f"open the vault at {dispath}", "vault open!"
                ):
                    return cls.deserialize(interaction, client, contents, where)

            except ClientError as ce:
                if ce.code != ClientError.ERR.DEVICE_INELIGIBLE:
                    raise ce
                print(
                    "This is the wrong authenticator.  Try touching a different one.",
                    file=sys.stderr,
                )

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
        Encrypt and store a password for the given service and username.
        """
        handle = KeyHandle.new(self.vault_handle.credential)
        with self.interaction.purpose(
            f"encrypt the password for {username!r} in {servicename!r}",
            "password encrypted and stored!",
        ):
            ciphertext = handle.encrypt_text(password)
            self.handles[servicename, username] = (handle, ciphertext)
            self.save()

    def get_password(self, servicename: str, username: str) -> str | None:
        """
        Retrieve a password for the .
        """
        key = (servicename, username)
        if key not in self.handles:
            print(f"No entry for {username!r} in {servicename!r}, not prompting", file=sys.stderr)
            return None
        handle, ciphertext = self.handles[key]
        try:
            with self.interaction.purpose(
                f"decrypt the password for {username!r} in {servicename!r}",
                "password decrypted!",
            ):
                plaintext = handle.decrypt_text(ciphertext)
        except ClientError as ce:
            if ce.code == ClientError.ERR.TIMEOUT:
                print("User presence check timed out.", file=sys.stderr)
                return None
            raise ce

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
