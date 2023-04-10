from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from getpass import getpass
from json import dump, dumps, load, loads
from os import fsync
from pathlib import Path
from typing import ClassVar, IO, Iterable, List, NoReturn, Optional, Sequence, TypedDict
from uuid import uuid4

from fido2.client import Fido2Client, UserInteraction
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


try:
    from fido2.pcsc import CtapPcscDevice

    have_pcsc = True
except ImportError:
    have_pcsc = False

from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode as encode_fernet_key


def enumerate_devices() -> Iterable[CtapHidDevice | CtapPcscDevice]:
    yield from CtapHidDevice.list_devices()
    if have_pcsc:
        yield from CtapPcscDevice.list_devices()


class ConsoleInteraction(UserInteraction):
    def prompt_up(self) -> None:
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]):
        print("User Verification required.")
        return True


class NoAuthenticator(Exception):
    """
    Could not find an authenticator.
    """


def locate_client() -> Fido2Client:
    # Locate a device
    for dev in enumerate_devices():
        client = Fido2Client(
            dev,
            "https://hardware.keychain.glyph.im",
            user_interaction=ConsoleInteraction(),
        )
        if "hmac-secret" in client.info.extensions:
            return client

    raise NoAuthenticator("No Authenticator with the HmacSecret extension found!")


SerializedCredentialHandle = dict[str, str]


@dataclass
class CredentialHandle:
    client: Fido2Client
    credential_id: bytes

    # Static parameters that have to be the same, but can have fairly arbitrary
    # values.
    rp: ClassVar[PublicKeyCredentialRpEntity] = PublicKeyCredentialRpEntity(
        id="hardware.keychain.glyph.im", name="Hardware Secret Keyring"
    )
    user: ClassVar[PublicKeyCredentialUserEntity] = PublicKeyCredentialUserEntity(
        id=b"hardware_keyring_user",
        name="Hardware Keyring User",
    )
    params: ClassVar[Sequence[PublicKeyCredentialParameters]] = [
        PublicKeyCredentialParameters(
            type=PublicKeyCredentialType.PUBLIC_KEY, alg=ES256.ALGORITHM
        )
    ]

    @classmethod
    def load(cls, client: Fido2Client, obj: dict[str, str]) -> CredentialHandle:
        """
        Load a key handle from a JSON blob.
        """
        assert obj["rp_id"] == cls.rp.id
        return CredentialHandle(
            client=client,
            credential_id=bytes.fromhex(obj["credential_id"]),
        )

    @classmethod
    def new_credential(cls, client: Fido2Client) -> CredentialHandle:
        """
        Create a new credential for generating keys on the device.
        """
        options = PublicKeyCredentialCreationOptions(
            rp=cls.rp,
            user=cls.user,
            challenge=os.urandom(32),
            pub_key_cred_params=cls.params,
            extensions={"hmacCreateSecret": True},
        )

        # Create a credential with a HmacSecret
        result = client.make_credential(options)

        # Sanity-check response.
        assert result.extension_results is not None
        assert result.extension_results.get("hmacCreateSecret") is not None

        credential = result.attestation_object.auth_data.credential_data
        assert credential is not None
        return CredentialHandle(client=client, credential_id=credential.credential_id)

    def key_from_salt(self, salt) -> bytes:
        """
        get the actual secret key from the hardware
        """
        allow_list = [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=self.credential_id,
            )
        ]
        challenge = os.urandom(32)
        options = PublicKeyCredentialRequestOptions(
            rp_id=self.rp.id,
            challenge=challenge,
            allow_credentials=allow_list,
            extensions={"hmacGetSecret": {"salt1": salt}},
        )
        # Only one cred in allowList, only one response.
        assertion_itself = self.client.get_assertion(options)
        assertion_result = assertion_itself.get_response(0)
        assert assertion_result.extension_results is not None
        output1 = assertion_result.extension_results["hmacGetSecret"]["output1"]
        return output1

    def serialize(self) -> SerializedCredentialHandle:
        """
        Serialize to JSON blob.
        """
        assert self.rp.id is not None
        return {
            "rp_id": self.rp.id,
            "credential_id": self.credential_id.hex(),
        }

    @classmethod
    def deserialize(
        cls,
        client: Fido2Client,
        obj: SerializedCredentialHandle,
    ) -> CredentialHandle:
        """
        Deserialize from JSON blob.
        """
        # TODO: check client serial number.
        return CredentialHandle(
            client=client, credential_id=bytes.fromhex(obj["credential_id"])
        )


class SerializedKeyHandle(TypedDict):
    salt: str
    credential: SerializedCredentialHandle


@dataclass
class KeyHandle:
    """
    The combination of a L{CredentialHandle} to reference key material on the
    device, and a random salt.
    """

    credential: CredentialHandle
    salt: bytes
    _saved_key: bytes | None = None

    @classmethod
    def new(cls, credential: CredentialHandle) -> KeyHandle:
        """
        Create a new KeyHandle.
        """
        return KeyHandle(credential, os.urandom(32))

    def remember_key(self) -> None:
        """
        Cache the bytes of the underlying key in memory so that we don't need
        to prompt the user repeatedly for subsequent authentications.
        """
        self._saved_key = self.key_as_bytes()

    def key_as_bytes(self) -> bytes:
        """
        Return 32 bytes suitable for use as an AES key.
        """
        saved = self._saved_key
        if saved is not None:
            return saved
        return self.credential.key_from_salt(self.salt)

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        """
        Encrypt some plaintext bytes.
        """
        key_bytes = self.key_as_bytes()
        fernet_key = encode_fernet_key(key_bytes)
        fernet = Fernet(fernet_key)
        ciphertext = fernet.encrypt(plaintext)
        return ciphertext

    def decrypt_bytes(self, ciphertext: bytes) -> bytes:
        """
        Decrypt some enciphered bytes.
        """
        key_bytes = self.key_as_bytes()
        fernet_key = encode_fernet_key(key_bytes)
        fernet = Fernet(fernet_key)
        plaintext = fernet.decrypt(ciphertext)
        return plaintext

    def encrypt_text(self, plaintext: str) -> str:
        """
        Encrypt some unicode text, returning text to represent it.
        """
        encoded = plaintext.encode("utf-8")
        cipherbytes = self.encrypt_bytes(encoded)
        return cipherbytes.hex()

    def decrypt_text(self, ciphertext: str) -> str:
        """
        Decrypt some hexlified bytes, returning the unicode text embedded in
        its plaintext.
        """
        decoded = bytes.fromhex(ciphertext)
        return self.decrypt_bytes(decoded).decode("utf-8")

    def serialize(self) -> SerializedKeyHandle:
        """
        Serialize to JSON-able data.
        """
        return {
            "salt": self.salt.hex(),
            "credential": self.credential.serialize(),
        }

    @classmethod
    def deserialize(cls, client: Fido2Client, obj: SerializedKeyHandle) -> KeyHandle:
        """ """
        return KeyHandle(
            credential=CredentialHandle.deserialize(client, obj["credential"]),
            salt=bytes.fromhex(obj["salt"]),
        )


class SerializedVault(TypedDict):
    """
    Serialized form of a L{Vault}
    """

    key: SerializedKeyHandle
    data: str


@dataclass
class Vault:
    """
    A vault where users may store multiple credentials.
    """

    client: Fido2Client
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
        cls, client: Fido2Client, obj: SerializedVault, where: Path
    ) -> Vault:
        """
        Deserialize the given vault from a fido2client.
        """
        vault_handle = KeyHandle.deserialize(client, obj["key"])
        vault_handle.remember_key()
        unlocked = vault_handle.decrypt_text(obj["data"])
        handlesobj = loads(unlocked)
        self = Vault(
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
    def create(cls, client: Fido2Client, where: Path) -> Vault:
        """
        Create a new Vault and save it in the given IO.
        """
        cred = CredentialHandle.new_credential(client)
        vault_key = KeyHandle.new(cred)
        vault_key.remember_key()
        self = Vault(client, vault_key, {}, where.absolute())
        self.save()
        return self

    @classmethod
    def load(cls, client: Fido2Client, where: Path) -> Vault:
        """
        Load an existing vault saved at a given path.
        """
        with where.open("r") as f:
            contents = load(f)
            print(contents)
        return cls.deserialize(client, contents, where)

    def save(self) -> None:
        """
        Save the vault to secondary storage.
        """
        print("saving vault...")
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
        print("saved.")

    def set_password(self, servicename: str, username: str, password: str) -> None:
        """
        Store a password for the tiven service and username.
        """
        handle = KeyHandle.new(self.vault_handle.credential)
        ciphertext = handle.encrypt_text(password)
        self.handles[servicename, username] = (handle, ciphertext)
        self.save()

    def get_password(self, servicename: str, username: str) -> str:
        """
        Retrieve a password.
        """
        handle, ciphertext = self.handles[servicename, username]
        plaintext = handle.decrypt_text(ciphertext)
        return plaintext

    def delete_password(self, servicename: str, username: str) -> None:
        """
        Delete a password.
        """
        del self.handles[servicename, username]
        self.save()


def create_vault(filename: str) -> None:
    client = locate_client()
    Vault.create(client, Path(filename))

def store_in(filename: str) -> None:
    client = locate_client()
    vault = Vault.load(client, Path(filename))
    service = input("Service?")
    user = input("User?")
    password = getpass("Password?")
    vault.set_password(service, user, password)

def cred_from_vault(filename: str) -> None:
    client = locate_client()
    vault = Vault.load(client, Path(filename))
    service = input("Service?")
    user = input("User?")
    print(vault.get_password(service, user))
