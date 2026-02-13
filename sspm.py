import getpass
import os
from pathlib import Path

import pyperclip
import typer
import rich
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console

PASS_DIR = Path.home() / ".sspm"

err_console = Console(stderr=True)

app = typer.Typer()


def get_salt() -> bytes:
    if not (PASS_DIR / "salt").exists():
        salt = os.urandom(16)
        with open(PASS_DIR / "salt", "wb") as arq:
            arq.write(salt)

    with open(PASS_DIR / "salt", "rb") as arq:
        salt = arq.read()

    return salt


def get_key(salt: bytes, master_password: bytes) -> bytes:
    hash = hash_secret_raw(
        secret=master_password,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )

    return hash


def get_crypt() -> AESGCM:
    master_password = getpass.getpass(prompt="Master Password: ").encode()
    salt = get_salt()
    key = get_key(salt, master_password)

    return AESGCM(key)


def validate_master(crypt: AESGCM) -> None:
    try:
        with open(PASS_DIR / "validator", "rb") as arq:
            content = arq.read()
            nonce = content[:12]
            ciphertext = content[12:]
            crypt.decrypt(nonce, ciphertext, b"auth").decode()
        return
    except InvalidTag:
        err_console.print("[bold red]Wrong password![/bold red]")


def save_password(crypt: AESGCM, name: str, password: str, aad: bytes | None = None) -> None:
    p = Path(name)
    dir_path = p.parent
    full_dir = PASS_DIR / dir_path
    full_path = full_dir / p.name

    if full_path.resolve() != full_path:
        err_console.print("[bold red]Invalid directory![/bold red]")
        return

    if dir_path != ".":
        full_dir.mkdir(parents=True, exist_ok=True)

    if full_path.exists():
        l = str(input(f"Password already exists for {full_path}. Overwrite it? [y/N]"))
        if l.lower() != "y":
            return

    nonce = os.urandom(12)
    ct = crypt.encrypt(nonce, password.encode(), aad)

    with open(full_path, "wb") as arq:
        arq.write(nonce + ct)
    print(f"Password {name} saved sucessfully")
    return


def load_password(name: str, crypt: AESGCM, aad: bytes | None = None) -> str:
    if not (PASS_DIR / name).exists():
        err_console.print(f"[bold red]Password {name} not found[/bold red]")
        typer.Exit()

    with open(PASS_DIR / name, "rb") as arq:
        content = arq.read()
        nonce = content[:12]
        ciphertext = content[12:]
        password = crypt.decrypt(nonce, ciphertext, aad).decode()
    return password


@app.command()
def init() -> None:
    try:
        os.mkdir(PASS_DIR)
    except OSError:
        err_console.print("[bold red]Password folder already exists[/bold red]")
        return

    save_password(get_crypt(), "validator", str(os.urandom(16)), b"auth")

    print(f"Password Manager initialized sucessfully at: {PASS_DIR}")
    return


@app.command()
def add(ctx: typer.Context, name: str) -> None:
    crypt = ctx.obj
    password = getpass.getpass(prompt=f"Enter password for {name}: ")
    confirm_password = getpass.getpass(prompt=f"Retype password for {name}: ")

    if password == confirm_password:
        save_password(crypt, name, password)
    else:
        err_console.print("[bold red]Passwords don't matches[/bold red]")
    return


@app.command()
def get(ctx: typer.Context, name: str) -> None:
    crypt = ctx.obj
    pyperclip.copy(load_password(name, crypt))
    print("Password copied to clipboard")
    return


@app.command()
def show(ctx: typer.Context, name: str) -> None:
    crypt = ctx.obj
    print(load_password(name, crypt))
    return


def tree(base_dir: Path, prefix: str = "") -> None:
    items = sorted(
        [it for it in base_dir.iterdir() if it.name not in ["salt", "validator"]]
    )

    for i, item in enumerate(items):
        is_last = i == len(items) - 1
        connector = "└── " if is_last else "├── "

        if item.is_dir():
            rich.print(f"{prefix}{connector}[bold blue]{item.name}[/bold blue]")
            new_prefix = prefix + ("    " if is_last else "│   ")
            tree(item, new_prefix)
        else:
            print(f"{prefix}{connector}{item.name}")
    return


@app.command()
def list() -> None:
    print("Passwords")
    tree(PASS_DIR)
    return


@app.command()
def rm(name: str) -> None:
    p = Path(name)
    full_path = PASS_DIR / p

    if full_path.resolve() != full_path:
        err_console.print("[bold red]Invalid directory![/bold red]")

    try:
        os.remove(full_path)
        if full_path.parent != PASS_DIR:
            os.removedirs(full_path.parent)
        print("Password removed sucessfully")
    except OSError:
        err_console.print("[bold red]Password not found[/bold red]")
    return


@app.callback()
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand == "init":
        return

    if not os.path.isdir(PASS_DIR):
        err_console.print("[bold red]Password manager not found, create with [init][/bold red]")
        typer.Exit()

    crypt = get_crypt()
    validate_master(crypt)
    ctx.obj = crypt


if __name__ == "__main__":
    app()
