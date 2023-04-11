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
from typing import Callable, ClassVar, IO, Iterable, Iterator, List, NoReturn, Optional, Sequence, TYPE_CHECKING, TypedDict
from uuid import uuid4

from fido2.client import ClientError, Fido2Client, UserInteraction
from fido2.cose import ES256
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.webauthn import AttestedCredentialData, AuthenticatorAttestationResponse, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity
from keyring.backend import KeyringBackend
from keyring.util.platform_ import data_root


try:
    from fido2.pcsc import CtapPcscDevice

    have_pcsc = True
except ImportError:
    have_pcsc = False

from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode as encode_fernet_key

if TYPE_CHECKING:
    AnyCtapDevice = CtapHidDevice | CtapPcscDevice


def enumerate_devices() -> Iterable[AnyCtapDevice]:
    yield from CtapHidDevice.list_devices()
    if have_pcsc:
        yield from CtapPcscDevice.list_devices()


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
    clients: Sequence[tuple[Fido2Client, AnyCtapDevice]]
) -> Fido2Client:
    """
    Select between different client devices we've discovered.
    """
    for idx, (client, device) in enumerate(clients):
        print(
            f"{1+idx}) {device.product_name} {device.serial_number} {getattr(getattr(device, 'descriptor', None), 'path', None)}"
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


def up_chooser(clients: Sequence[Fido2Client]) -> Fido2Client:
    """
    Choose a client from the given list of clients by prompting for user
    presence on one of them.  Does not work because of U{this bug
    <https://github.com/Yubico/python-fido2/issues/184>}.
    """
    cancel = Event()
    selected: Fido2Client | None = None

    def select(client: Fido2Client) -> None:
        nonlocal selected
        try:
            client.selection(cancel)
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


class NoAuthenticator(Exception):
    """
    Could not find an authenticator.
    """


def enumerate_clients(interaction: UserInteraction) -> Iterable[tuple[Fido2Client, AnyCtapDevice]]:
    # Locate a device
    for dev in enumerate_devices():
        yield (
            Fido2Client(
                dev,
                "https://hardware.keychain.glyph.im",
                user_interaction=interaction,
            ),
            dev,
        )


def extension_required(client: Fido2Client) -> bool:
    """
    Client filter for clients that support the hmac-secret extension.
    """
    has_extension = "hmac-secret" in client.info.extensions
    return has_extension


def select_client(
    interaction: UserInteraction,
    filters: Sequence[Callable[[Fido2Client], bool]],
    choose: Callable[[Sequence[tuple[Fido2Client, AnyCtapDevice]]], Fido2Client],
) -> Fido2Client:
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

    interaction: ConsoleInteraction
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
        cls, interaction: ConsoleInteraction, client: Fido2Client, obj: SerializedVault, where: Path
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
        with self.interaction.purpose(f"encrypt the password for {servicename}/{username}"):
            ciphertext = handle.encrypt_text(password)
        self.handles[servicename, username] = (handle, ciphertext)
        self.save()

    def get_password(self, servicename: str, username: str) -> str:
        """
        Retrieve a password.
        """
        handle, ciphertext = self.handles[servicename, username]
        with self.interaction.purpose(f"decrypt the password for {servicename}/{username}"):
            plaintext = handle.decrypt_text(ciphertext)
        return plaintext

    def delete_password(self, servicename: str, username: str) -> None:
        """
        Delete a password.
        """
        del self.handles[servicename, username]
        self.save()


@dataclass
class LocalCTAP2KeyringBackend(KeyringBackend):
    """
    Keyring backend implementation for L{Vault}
    """

    vault: Vault | None = None
    location: Path = Path(data_root()) / "keyring.ctap2vault"
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
    LocalCTAP2KeyringBackend()


def create_vault(filename: str) -> None:
    Vault.create(Path(filename))


def store_in(filename: str) -> None:
    vault = Vault.load(Path(filename))
    service = input("Service?")
    user = input("User?")
    password = getpass("Password?")
    vault.set_password(service, user, password)


def cred_from_vault(filename: str) -> None:
    vault = Vault.load(Path(filename))
    service = input("Service?")
    user = input("User?")
    print(vault.get_password(service, user))
