import os
import subprocess
from getpass import getpass
from pathlib import Path
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich import print
from rich.console import Console

PASS_DIR = Path.home() / ".sspm"
err_console = Console(stderr=True)


class Vault:
    def __init__(self):
        self.pass_dir = PASS_DIR
        self._crypt: Optional[AESGCM] = None

    @property
    def crypt(self) -> AESGCM:
        if self._crypt is None:
            raise RuntimeError("Vault not autenticated")
        return self._crypt

    def initialize_master(self):
        pswd = getpass(prompt="Master Password: ").encode()
        salt = self._get_or_create_salt()
        key = hash_secret_raw(
            secret=pswd,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )
        self._crypt = AESGCM(key)
        self._validate()

    def _get_or_create_salt(self) -> bytes:
        salt_path = self.pass_dir / ".salt"
        if not salt_path.exists():
            self.pass_dir.mkdir(parents=True, exist_ok=True)
            salt = os.urandom(16)
            salt_path.write_bytes(salt)
        return salt_path.read_bytes()

    def _validate(self):
        val_path = self.pass_dir / ".validator"
        if not val_path.exists():
            return
        try:
            data = val_path.read_bytes()
            self.crypt.decrypt(data[:12], data[12:], b"auth")
        except InvalidTag:
            err_console.print("[bold red]Wrong password![/bold red]")
            raise SystemExit(1)

    def save(self, name: str, content: str, aad: bytes | None = None):
        full_path = (self.pass_dir / name).resolve()
        if not str(full_path).startswith(str(self.pass_dir)):
            err_console.print("[bold red]Invalid path![/bold red]")
            raise SystemExit(1)

        if full_path.exists():
            c = str(
                input(f"Password already exists for {full_path}. Overwrite it? [y/N] ")
            )
            if c.lower() != "y":
                print("Operation canceled")
                raise SystemExit(0)

        full_path.parent.mkdir(parents=True, exist_ok=True)
        nonce = os.urandom(12)
        ct = self.crypt.encrypt(nonce, content.encode(), aad)
        full_path.write_bytes(nonce + ct)
        self.git_commit("update/insert", name)

    def load(self, name: str, aad: bytes | None = None):
        path = self.pass_dir / name
        if not path.exists():
            err_console.print(f"[bold red]Password {name} not found[/bold red]")
            raise SystemExit(1)

        data = path.read_bytes()
        return self.crypt.decrypt(data[:12], data[12:], aad).decode()

    def remove(self, name: str):
        full_path = (self.pass_dir / name).resolve()
        if not str(full_path).startswith(str(self.pass_dir)):
            err_console.print("[bold red]Invalid path![/bold red]")
            raise SystemExit(1)

        if not full_path.exists():
            err_console.print("[bold red]Password not found[/bold red]")
            raise SystemExit(1)

        try:
            full_path.unlink()
            current_dir = full_path.parent
            while current_dir != self.pass_dir and current_dir.is_relative_to(
                self.pass_dir
            ):
                if not any(current_dir.iterdir()):
                    current_dir.rmdir()
                    current_dir = current_dir.parent
                else:
                    break

            self.git_commit("remove", name)
        except OSError as e:
            err_console.print(f"[bold red]Could not delete: {e}[/bold red]")
            raise SystemExit(1)

    def git_commit(self, action: str, item: str):
        if (self.pass_dir / ".git").exists():
            subprocess.run(
                ["git", "-C", str(self.pass_dir), "add", "."], capture_output=True
            )
            subprocess.run(
                ["git", "-C", str(self.pass_dir), "commit", "-m", f"{action}: {item}"],
                capture_output=True,
            )


def list_tree(base_dir: Path, prefix: str = "") -> None:
    items = sorted([it for it in base_dir.iterdir() if not it.name.startswith(".")])

    for i, item in enumerate(items):
        is_last = i == len(items) - 1
        connector = "└── " if is_last else "├── "

        if item.is_dir():
            print(f"{prefix}{connector}[bold blue]{item.name}[/bold blue]")
            new_prefix = prefix + ("    " if is_last else "│   ")
            list_tree(item, new_prefix)
        else:
            print(f"{prefix}{connector}{item.name}")
    return
