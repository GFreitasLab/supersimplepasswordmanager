import getpass
import os
from pathlib import Path

import pyperclip
import typer
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASS_DIR = Path.home() / ".sspm"

app = typer.Typer()


def get_salt() -> bytes:
    try:
        with open(PASS_DIR / "salt", "rb") as arq:
            salt = arq.read()
    except:
        salt = os.urandom(16)
        with open(PASS_DIR / "salt", "wb") as arq:
            arq.write(salt)
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
        print("Wrong password")
    exit()


def save_password(crypt: AESGCM, name: str, password: str, aad=None) -> None:
    p = Path(name)
    dir_path = p.parent
    full_dir = PASS_DIR / dir_path
    full_path = full_dir / p.name

    if full_path.resolve() != full_path:
        print("Invalid directory")
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


def load_password(name: str, crypt: AESGCM, aad=None) -> str:
    try:
        with open(PASS_DIR / name, "rb") as arq:
            content = arq.read()
            nonce = content[:12]
            ciphertext = content[12:]
            password = crypt.decrypt(nonce, ciphertext, aad).decode()
        return password
    except:
        print(f"Password {name} not found")
        exit()


@app.command()
def init() -> None:
    try:
        os.mkdir(PASS_DIR)
    except OSError:
        print("Password folder already exists")
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
        print("Passwords don't matches")
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
            typer.echo(f"{prefix}{connector}", nl=False)
            typer.secho(f"{item.name}", fg=typer.colors.BLUE, bold=True)

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
        print("Invalid directory")

    try:
        os.remove(full_path)
        if full_path.parent != PASS_DIR:
            os.removedirs(full_path.parent)
        print("Password removed sucessfully")
    except OSError:
        print("Password not found")
    return


@app.callback()
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand == "init":
        return

    if not os.path.isdir(PASS_DIR):
        print("Password manager not found, create with [init]")
        exit()

    crypt = get_crypt()
    validate_master(crypt)
    ctx.obj = crypt


if __name__ == "__main__":
    app()
