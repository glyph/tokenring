from pathlib import Path
from platform import win32_edition
from os import urandom

from keyring.util.platform_ import data_root

keyringdir = Path(data_root()).absolute()
keyringdir.mkdir(parents=True, exist_ok=True)

if win32_edition() is not None:
    from getpass import getuser

    family = "AF_PIPE"
    address = rf"\\.\pipe\{getuser()}-TokenVault"
else:
    from getpass import getuser

    family = "AF_UNIX"
    address = (keyringdir / "tokenring.socket").as_posix()

secret_path = keyringdir / "tokenring.socket-secret"
if secret_path.is_file():
    auth_key = secret_path.read_bytes()
else:
    auth_key = urandom(32)
    secret_path.write_bytes(auth_key)
