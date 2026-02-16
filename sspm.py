import os
import secrets
import string
import subprocess
from getpass import getpass

import pyperclip
import typer

from core import PASS_DIR, Vault, err_console, list_tree

app = typer.Typer()
vault = Vault()


@app.command()
def init() -> None:
    """Initalize the vault"""
    if PASS_DIR.exists():
        err_console.print("[bold red]Password folder already exists[/bold red]")
        return
    vault.initialize_master()
    vault.save(".validator", os.urandom(16).hex(), b"auth")
    print(f"Password Manager initialized sucessfully at: {PASS_DIR}")


@app.command()
def insert(name: str) -> None:
    """Add or overwrite a password"""
    pswd = getpass(prompt=f"Password for {name}: ")

    if pswd == getpass("Confirm: "):
        vault.save(name, pswd)
    else:
        err_console.print("[bold red]Passwords don't matches[/bold red]")


@app.command()
def copy(name: str) -> None:
    """Copy password to clipboard"""
    pyperclip.copy(vault.load(name))
    print("Password copied to clipboard")


@app.command()
def generate(name: str) -> None:
    """Generate a random password"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    pswd = "".join(secrets.choice(alphabet) for _ in range(20))
    vault.save(name, pswd)
    print(f"The password generated for {name} is:\n{pswd}")


@app.command()
def show(name: str) -> None:
    """Display password in terminal"""
    print(vault.load(name))


@app.command()
def list() -> None:
    """List all password in a tree format"""
    print("Passwords")
    list_tree(PASS_DIR)


@app.command()
def remove(name: str) -> None:
    """Delete a password entry"""
    l = str(input(f"Are you sure you would like to delete {name}? [y/N] "))
    if l.lower() != "y":
        return
    vault.remove(name)
    print(f"Password {name} removed sucessfully")


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def git(ctx: typer.Context):
    """Uses git commands in vault directory"""
    if not PASS_DIR.exists():
        err_console.print("[bold red]Password directory does not exist[/bold red]")
        return
    command = ["git", "-C", str(PASS_DIR)] + ctx.args
    try:
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            err_console.print(
                f"[bold red]Git command failed with code {result.returncode}[/bold red]"
            )
    except FileNotFoundError:
        err_console.print("[bold red]Git not found. Is it installed?[/bold red]")


@app.callback()
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand != "init":
        if not PASS_DIR.exists():
            err_console.print(
                "[bold red]Password manager not found, create with [init][/bold red]"
            )
            raise typer.Exit(1)
        vault.initialize_master()


if __name__ == "__main__":
    app()
