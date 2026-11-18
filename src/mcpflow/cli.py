"""The `mcpflow` console entry point.

`serve` runs the gateway with uvicorn. `set-admin-password` writes the admin
password file that the next start applies. `hash-password` prints a password
hash. Flags override environment variables.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__
from .auth import hash_password
from .config import ConfigError, data_dir_path, load_settings
from .identity import LocalIdentityProvider, write_admin_password_file


def _serve(args: argparse.Namespace) -> int:
    overrides: dict[str, str] = {}
    if args.host is not None:
        overrides["HOST"] = args.host
    if args.port is not None:
        overrides["PORT"] = str(args.port)
    if args.data_dir is not None:
        overrides["DATA_DIR"] = args.data_dir
    try:
        settings = load_settings(overrides)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    import uvicorn

    from .gateway import build_app

    uvicorn.run(
        build_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
    )
    return 0


def _hash_password(args: argparse.Namespace) -> int:
    password = (
        args.password if args.password is not None else getpass.getpass("Password: ")
    )
    print(hash_password(password))
    return 0


def _set_admin_password(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir) if args.data_dir else data_dir_path()
    try:
        password = getpass.getpass("New admin password: ")
        repeat = getpass.getpass("Repeat the password: ")
    except (EOFError, KeyboardInterrupt):
        print("No password read. Nothing was written.", file=sys.stderr)
        return 1
    if password != repeat:
        print("The two passwords differ.", file=sys.stderr)
        return 2
    try:
        LocalIdentityProvider.check_new_password(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        path = write_admin_password_file(data_dir, hash_password(password))
    except OSError as exc:
        print(f"Could not write the password file: {exc.strerror or exc}", file=sys.stderr)
        return 1
    print(
        f"Wrote {path}. Restart mcpflow to apply it. Every admin browser session "
        "ends then; bearer tokens stay valid, revoke them on the tokens page."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcpflow")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the gateway")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--data-dir", dest="data_dir")
    serve.set_defaults(func=_serve)

    sap = sub.add_parser(
        "set-admin-password", help="write the admin password file for the next start"
    )
    sap.add_argument("--data-dir", dest="data_dir")
    sap.set_defaults(func=_set_admin_password)

    hp = sub.add_parser("hash-password", help="print a password hash")
    hp.add_argument("password", nargs="?")
    hp.set_defaults(func=_hash_password)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
