from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
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

    def get_password(self, servicename: str, username: str) -> str | None:
        return self.realize_vault().get_password(servicename, username)

    def set_password(self, servicename: str, username: str, password: str) -> None:
        self.realize_vault().set_password(servicename, username, password)


if TYPE_CHECKING:
    LocalTokenRing()
