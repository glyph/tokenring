from dataclasses import dataclass

from .local import LocalCTAP2KeyringBackend


_global_vault: LocalCTAP2KeyringBackend | None


def get_vault() -> LocalCTAP2KeyringBackend:
    global _global_vault
    if _global_vault is None:
        _global_vault = LocalCTAP2KeyringBackend()
    return _global_vault


@dataclass
class GetPassword:
    servicename: str
    username: str

    def do(self) -> str:
        return get_vault().get_password(self.servicename, self.username)


@dataclass
class SetPassword:
    servicename: str
    username: str
    password: str

    def do(self) -> None:
        return get_vault().set_password(self.servicename, self.username, self.password)
