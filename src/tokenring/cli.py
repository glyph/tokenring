import sys
from getpass import getpass
from multiprocessing.connection import Listener
from pathlib import Path

from pyuac import main_requires_admin  # type:ignore[import]

import click

from .agent.common import address, auth_key, family
from .agent.client import BackgroundTokenRing

if sys.platform == "win32":
    from .agent._admin_pipe import _patch

    _patch()


from .local import LocalTokenRing

# Windows requires administrator access in order to access the hmac-secret
# extension on the hard token, to get direct USB HID access to the device,
# because of this bug:

# https://github.com/Yubico/python-fido2/issues/185

def token_ring() -> BackgroundTokenRing | LocalTokenRing:
    if BackgroundTokenRing.connection is not None:
        return BackgroundTokenRing()
    else:
        return LocalTokenRing()

@click.group()
def cli():
    ...

@cli.command()
@click.argument('servicename')
@click.argument('username')
def get(servicename: str, username: str) -> None:
    click.echo(token_ring().get_password(servicename, username))

@cli.command()
@click.argument('servicename')
@click.argument('username')
def set(servicename: str, username: str) -> None:
    password = getpass(f"Password for '{username}' in '{servicename}': ")
    token_ring().set_password(servicename, username, password)


click_path = click.Path(path_type=Path)  # type:ignore[type-var]
# type ignore here seems to be just a bug in types-click?

from sys import argv
real_argv = argv[:]
@cli.command()
@click.argument("vault_path", required=False, type=click_path)
@main_requires_admin(cmdLine=real_argv)
def agent(vault_path: Path | None) -> None:

    local_ring = (
        LocalTokenRing(location=vault_path)
        if vault_path is not None
        else LocalTokenRing()
    )

    vault = local_ring.realize_vault()
    with Listener(address=address, family=family, authkey=auth_key) as listener:
        while True:
            with listener.accept() as conn:
                while True:
                    password = None
                    try:
                        command = conn.recv_bytes()
                    except EOFError:
                        break
                    else:
                        if command == b"get":
                            servicename = conn.recv_bytes().decode("utf-8")
                            username = conn.recv_bytes().decode("utf-8")
                            password = vault.get_password(servicename, username)
                            if password is None:
                                conn.send_bytes(b"n")
                            else:
                                conn.send_bytes(b"y")
                                conn.send_bytes(password.encode("utf-8"))
                                password = None

                        if command == b"set":
                            servicename = conn.recv_bytes().decode("utf-8")
                            username = conn.recv_bytes().decode("utf-8")
                            password = conn.recv_bytes().decode("utf-8")
                            vault.set_password(servicename, username, password)
                            password = None
                            conn.send_bytes(b"n")
