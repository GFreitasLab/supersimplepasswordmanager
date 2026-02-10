import base64
import getpass
import os
from pathlib import Path

import pyperclip
import typer
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=120000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    return key


def get_fernet() -> Fernet:
    master_password = getpass.getpass(prompt="Master Password: ").encode()
    salt = get_salt()
    key = get_key(salt, master_password)
    return Fernet(key)


def validate_master(f: Fernet) -> None:
    try:
        with open(PASS_DIR / "validator", "rb") as arq:
            validator = arq.read()
            f.decrypt(validator)
        return
    except InvalidToken:
        print("Wrong password")
    exit()


def save_password(dir: str, password: bytes) -> None:
    try:
        os.makedirs(PASS_DIR / dir)
    except OSError:
        opt = str(input(f"A password already exists for {dir}. Overwrite it? [Y/n] "))
        if opt.lower() != "y":
            print("Save canceled")
            return
    with open(PASS_DIR / dir / "password", "wb") as arq:
        arq.write(password)
    print(f"Password for {dir} saved sucessfully")
    return


def load_password(dir: str, f: Fernet) -> str:
    try:
        with open(PASS_DIR / dir / "password", "rb") as arq:
            encrypted_password = arq.read()
            password = f.decrypt(encrypted_password).decode()
        return password
    except:
        print(f"Password in {dir} not found")
        exit()


@app.command()
def init() -> None:
    try:
        os.mkdir(PASS_DIR)
    except OSError:
        print("Password folder already exists")
        return
    f = get_fernet()
    validator = f.encrypt(os.urandom(16))

    with open(f"{PASS_DIR}/validator", "wb") as f:
        f.write(validator)

    print(f"Password Manager initialized sucessfully at: {PASS_DIR}")
    return


@app.command()
def add(ctx: typer.Context, name: str) -> None:
    f = ctx.obj
    password = getpass.getpass(prompt=f"Enter password for {name}: ")
    confirm_password = getpass.getpass(prompt=f"Retype password for {name}: ")

    if password == confirm_password:
        encrypted_data = f.encrypt(password.encode())
        save_password(name, encrypted_data)
    else:
        print("Passwords don't matches")
    return


@app.command()
def get(ctx: typer.Context, name: str) -> None:
    f = ctx.obj
    pyperclip.copy(load_password(name, f))
    print("Password copied to clipboard")
    return


@app.command()
def show(ctx: typer.Context, name: str) -> None:
    f = ctx.obj
    print(load_password(name, f))
    return


def tree(base_dir: Path, pref: str = "   ", lv: int = 0) -> None:
    dirs = sorted([item for item in base_dir.iterdir() if item.is_dir()])

    if not dirs:
        return

    dirs_size = len(dirs)
    for i in range(0, dirs_size):
        if i < dirs_size - 1:
            print(f"{pref * lv}├── {dirs[i].name}")
            tree(dirs[i], "│   ", lv + 1)
        else:
            print(f"{pref * lv}└── {dirs[i].name}")
    return


@app.command()
def list() -> None:
    print("Passwords")
    tree(PASS_DIR)
    return


@app.command()
def rm(name: str) -> None:
    try:
        os.remove(PASS_DIR / name / "password")
        os.removedirs(PASS_DIR / name)
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

    f = get_fernet()
    validate_master(f)
    ctx.obj = f


if __name__ == "__main__":
    app()
