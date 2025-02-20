from __future__ import annotations

import os
from base64 import urlsafe_b64encode as encode_fernet_key
from dataclasses import dataclass
from typing import (
    Any,
    ClassVar,
    Sequence,
    TypedDict,
)

from cryptography.fernet import Fernet
from fido2.cose import ES256
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
)

from .fidoclient import AnyFidoClient

SerializedCredentialHandle = dict[str, str]

def platform_specific_extract_extension_results(results: Any)->bytes:
    """
    There's a bug in python-fido2 which reflects extension output values as
    literal dictionaries full of bytes on Windows (which is what it used to do
    everywhere) and magical dict-proxy-but-also-has-some-attributes objects on
    all other platforms, where the other platforms reflect the dict-ish values
    as base64-encoded strings and the extra attributes they provide (but do not
    provide type annotations for) are the original bytes.
    """
    if os.name == 'nt':
        return results["hmacGetSecret"]["output1"]
    else:
        return results.hmacGetSecret.output1


@dataclass
class CredentialHandle:
    client: AnyFidoClient
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
    def load(cls, client: AnyFidoClient, obj: dict[str, str]) -> CredentialHandle:
        """
        Load a key handle from a JSON blob.
        """
        assert obj["rp_id"] == cls.rp.id
        return CredentialHandle(
            client=client,
            credential_id=bytes.fromhex(obj["credential_id"]),
        )

    @classmethod
    def new_credential(cls, client: AnyFidoClient) -> CredentialHandle:
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

    def key_from_salt(self, salt: bytes) -> bytes:
        """
        Get the actual secret key from the hardware.

        Note that this requires user verification.
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
        assertion_result: Any = assertion_itself.get_response(0)
        assert assertion_result.extension_results is not None
        output1: bytes = platform_specific_extract_extension_results(assertion_result.extension_results)
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
        client: AnyFidoClient,
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
        key_bytes: bytes = self.key_as_bytes()
        fernet_key = encode_fernet_key(key_bytes)
        fernet = Fernet(fernet_key)
        ciphertext = fernet.encrypt(plaintext)
        return ciphertext

    def decrypt_bytes(self, ciphertext: bytes) -> bytes:
        """
        Decrypt some enciphered bytes.
        """
        key_bytes: bytes = self.key_as_bytes()
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
    def deserialize(cls, client: AnyFidoClient, obj: SerializedKeyHandle) -> KeyHandle:
        """ """
        return KeyHandle(
            credential=CredentialHandle.deserialize(client, obj["credential"]),
            salt=bytes.fromhex(obj["salt"]),
        )
