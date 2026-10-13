"""Users, groups, and the one interface every component asks about them.

`IdentityProvider` is the seam: sign-in, lookup, groups, the admin role, and
the session binding. `LocalIdentityProvider` owns `DATA_DIR/users.json`. No
other module reads that file. Every mutator validates, builds a candidate
state, writes the file atomically, and only then adopts the candidate in
memory, the same rule as `Registry._commit`.

A Local user is active or pending. An active user holds a password hash. A
pending user holds the hash `""` and an optional `setup` object, the SHA-256
digest and expiry of a one-time setup code. The provider owns every move
between the two states: `_create_user` and `_issue_setup_code` make a user
pending, and `replace_credential`, a compare-and-swap, makes it active. No
operation sets a password that another user chose.

The admin role is membership of the reserved group `admins`: `User.is_admin`
is derived from `groups`, and no record stores the role apart from them. The
group always exists and cannot be deleted. Group changes go through
`change_groups`, a delta of one synchronous read and write, so a stale form
changes only the groups it toggled.

The bootstrap user `admin` follows three rules: the environment owns its
password hash at every start, it is always a member of `admins`, and no
operation deletes it, removes it from `admins`, replaces its credential, or
issues a setup code for it, so it is never pending.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol

from .auth import hash_password, verify_password

if TYPE_CHECKING:
    from fastmcp.server.auth.auth import AccessToken

# A user id is the stable subject. It excludes `@` and `.`, because a server
# reference (`<namespace>@<owner>`) and the session cookie use them as
# separators. It admits a lowercase UUID, the Keycloak `sub` of a later phase.
USER_ID_RE: re.Pattern[str] = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
GROUP_RE: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
BOOTSTRAP_ADMIN_ID: Final = "admin"
ADMINS_GROUP: Final = "admins"  # the reserved group; membership is the admin role
SETUP_CODE_TTL: Final = 7 * 24 * 3600  # seconds a setup code stays valid
MIN_PASSWORD_LENGTH: Final = 8
_SHA256_HEX_RE: re.Pattern[str] = re.compile(r"[0-9a-f]{64}")
_BOOTSTRAP_IN_ADMINS: Final = f"cannot remove the bootstrap user {BOOTSTRAP_ADMIN_ID} from {ADMINS_GROUP}"


# Keyword-only, so an old positional construction with an `is_admin` value
# raises `TypeError` instead of shifting a bool into `provider`.
@dataclass(frozen=True, kw_only=True)
class User:
    id: str
    name: str
    groups: frozenset[str]
    provider: str  # "local" in P1
    # A status, not a secret: True only for a Local user who has not yet set
    # a password through a setup code.
    pending: bool = False
    # The incarnation of this id in this process. `_create_user` of an id
    # that this process deleted starts the next one; no other write
    # changes it. Not persisted: no snapshot outlives the process.
    incarnation: int = 0

    @property
    def is_admin(self) -> bool:
        return ADMINS_GROUP in self.groups


class IdentityProvider(Protocol):
    kind: str

    def authenticate(self, user_id: str, password: str) -> User | None: ...

    def get_user(self, user_id: str) -> User | None: ...

    def resolve(self, token: AccessToken) -> User | None: ...

    def list_users(self) -> list[User]: ...

    def list_groups(self) -> list[str]: ...

    def session_binding(self, user_id: str) -> str | None: ...


def _parse(data: Any) -> tuple[dict[str, dict], list[str]]:
    """Validate a `users.json` payload. Raise `ValueError` on any fault.

    A malformed file stops the start: a lenient load could drop a user or a
    group membership, and a dropped membership silently changes a grant.

    Version 1 and version 2 parse to the version 2 shape. A version 1 file
    migrates in memory (design D3): its `admin` flag becomes membership of
    `admins`. Pure: `load` decides whether to write.
    """
    version = data.get("version") if isinstance(data, dict) else None
    if type(version) is not int or version not in (1, 2):
        raise ValueError("users.json: expected an object with version 1 or 2")
    raw_groups = data.get("groups", [])
    raw_users = data.get("users", [])
    if not isinstance(raw_groups, list) or not isinstance(raw_users, list):
        raise ValueError("users.json: users and groups must be lists")  # noqa: TRY004 -- a malformed file is a ValueError by contract
    groups: list[str] = []
    for name in raw_groups:
        if not isinstance(name, str) or not GROUP_RE.fullmatch(name) or name in groups:
            raise ValueError(f"users.json: bad or duplicate group {name!r}")
        groups.append(name)
    users: dict[str, dict] = {}
    legacy_admins: set[str] = set()  # version 1 users with `admin: true`
    for rec in raw_users:
        if not isinstance(rec, dict):
            raise ValueError("users.json: a user record must be an object")  # noqa: TRY004 -- see above
        user_id = rec.get("id")
        if not isinstance(user_id, str) or not USER_ID_RE.fullmatch(user_id):
            raise ValueError(f"users.json: bad user id {user_id!r}")
        if user_id in users:
            raise ValueError(f"users.json: duplicate user {user_id}")
        if version == 2 and "admin" in rec:
            raise ValueError(f"users.json: version 2 record for user {user_id} holds admin")
        name = rec.get("name", "")
        password_hash = rec.get("password_hash")
        admin = rec.get("admin", False)
        member = rec.get("groups", [])
        if (
            not isinstance(name, str)
            or not isinstance(password_hash, str)
            or not isinstance(admin, bool)
            or not isinstance(member, list)
            or any(g not in groups for g in member)
        ):
            raise ValueError(f"users.json: malformed record for user {user_id}")
        out = {
            "id": user_id,
            "name": name,
            "password_hash": password_hash,
            "groups": sorted(set(member)),
        }
        if admin:
            legacy_admins.add(user_id)
        if "setup" in rec:
            # Only a pending user (hash "") holds a setup code.
            if password_hash:
                raise ValueError(f"users.json: active user {user_id} holds a setup object")
            setup = rec["setup"]
            sha = setup.get("sha256") if isinstance(setup, dict) else None
            expires_at = setup.get("expires_at") if isinstance(setup, dict) else None
            if (
                not isinstance(sha, str)
                or not _SHA256_HEX_RE.fullmatch(sha)
                or not isinstance(expires_at, int)
                or isinstance(expires_at, bool)
            ):
                raise ValueError(f"users.json: bad setup object for user {user_id}")
            out["setup"] = {"sha256": sha, "expires_at": expires_at}
        users[user_id] = out
    if version == 1:
        # A legacy group `admins` with a non-admin member would make that
        # member an admin on merge. Refuse; renaming it also means
        # `rules.json`, which this provider does not own.
        conflict = sorted(
            uid
            for uid, rec in users.items()
            if ADMINS_GROUP in rec["groups"]
            and uid not in legacy_admins
            and uid != BOOTSTRAP_ADMIN_ID
        )
        if conflict:
            raise ValueError(
                f"users.json: version 1 group {ADMINS_GROUP} holds non-admin users "
                f"{', '.join(conflict)}; rename that group before the upgrade"
            )
        if ADMINS_GROUP not in groups:
            groups.append(ADMINS_GROUP)
        for uid in legacy_admins:
            users[uid]["groups"] = sorted({*users[uid]["groups"], ADMINS_GROUP})
    return users, groups


class LocalIdentityProvider:
    """The phase 1 provider. Implements `IdentityProvider`; `kind` is "local"."""

    kind = "local"

    def __init__(
        self,
        path: Path,
        admin_password_hash: str,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = path
        self._admin_password_hash = admin_password_hash
        self._clock = clock  # the setup-code expiry reads it; a test moves it
        self._users: dict[str, dict] = {}
        self._groups: list[str] = []
        # Every id this process has seen, deleted ids included, mapped to
        # its incarnation. In memory only: `users.json` never holds it.
        self._incarnations: dict[str, int] = {}
        # Set in `load`. Before `load` the store holds no user, so no sign-in
        # can succeed and nothing depends on the cost of this check.
        self._dummy_hash = ""

    def load(self) -> None:
        version = None
        if self._path.exists():
            data = json.loads(self._path.read_text())
            version = data.get("version") if isinstance(data, dict) else None
            # Raises on a malformed file or a conflicting legacy `admins`
            # group, before the bootstrap rules and before any write.
            parsed = _parse(data)
        else:
            parsed = ({}, [])
        users, groups = parsed
        # The bootstrap rules, applied at every start. The environment owns
        # the admin password, so a rotation of `ADMIN_PASSWORD` takes effect
        # here; the membership of `admins` is forced back on, so a hand edit
        # cannot demote it.
        if ADMINS_GROUP not in groups:
            groups = [*groups, ADMINS_GROUP]
        current = users.get(BOOTSTRAP_ADMIN_ID)
        users = {
            **users,
            BOOTSTRAP_ADMIN_ID: {
                "id": BOOTSTRAP_ADMIN_ID,
                "name": current["name"] if current else BOOTSTRAP_ADMIN_ID,
                "password_hash": self._admin_password_hash,
                "groups": sorted({*(current["groups"] if current else ()), ADMINS_GROUP}),
            },
        }
        # One write: a version 1 file always migrates; a version 2 file that
        # already satisfies the rules writes nothing (idempotent load).
        if version == 1 or (users, groups) != parsed:
            self._save(users, groups)
        self._users, self._groups = users, groups
        # Never lowers an entry: a second `load` keeps a re-created id.
        for uid in users:
            self._incarnations.setdefault(uid, 0)
        # One sign-in of an unknown or pending user verifies against this
        # hash, so it costs the same `pbkdf2_sha256` work as an active user.
        # The iteration count is the `hash_password` default, the one
        # every stored hash uses.
        self._dummy_hash = hash_password(secrets.token_hex(16))

    def _save(self, users: dict[str, dict], groups: list[str]) -> None:
        """Write a candidate state. The caller adopts it only after this returns."""
        payload = {
            "version": 2,
            "groups": list(groups),
            "users": [users[k] for k in sorted(users)],
        }
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        # Create the file already-private (0600); the hashes never sit at
        # 0644 in the write window.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(payload, indent=2))
        os.replace(tmp, self._path)

    # --- reads -------------------------------------------------------------

    def _to_user(self, rec: dict) -> User:
        return User(
            id=rec["id"],
            name=rec["name"] or rec["id"],
            groups=frozenset(rec["groups"]),
            provider=self.kind,
            pending=rec["password_hash"] == "",
            incarnation=self._incarnations.get(rec["id"], 0),
        )

    def authenticate(self, user_id: str, password: str) -> User | None:
        """Return the user when the password matches, else `None`.

        Exactly one `pbkdf2_sha256` verification on every path: an unknown
        or pending user verifies against the dummy hash, so the time does
        not tell whether the user exists or is pending.
        """
        rec = self._users.get(user_id)
        if rec is None or not rec["password_hash"]:
            verify_password(password, self._dummy_hash)
            return None
        if not verify_password(password, rec["password_hash"]):
            return None
        return self._to_user(rec)

    def get_user(self, user_id: str) -> User | None:
        rec = self._users.get(user_id)
        return None if rec is None else self._to_user(rec)

    def resolve(self, token: AccessToken) -> User | None:
        """The user that `token.subject` names; `None` without a subject."""
        subject = getattr(token, "subject", None)
        if not subject:
            return None
        return self.get_user(subject)

    def list_users(self) -> list[User]:
        return [self._to_user(self._users[k]) for k in sorted(self._users)]

    def list_groups(self) -> list[str]:
        return list(self._groups)

    def session_binding(self, user_id: str) -> str | None:
        """The value a session cookie binds: the password hash.

        A password change therefore invalidates every session of the user.
        A pending user has `None`, never the stored `""`: `""` repeats in
        every pending period, so a binding read before a redeem and one
        after a later reset would be equal and the sign-in route would sign
        `""` (ABA, design D5). `None` never signs.
        """
        rec = self._users.get(user_id)
        if rec is None or not rec["password_hash"]:
            return None
        return rec["password_hash"]

    # --- mutators ----------------------------------------------------------

    def _record(self, user_id: str) -> dict:
        try:
            return self._users[user_id]
        except KeyError:
            raise KeyError(user_id) from None

    def _check_groups(self, groups: Iterable[str]) -> list[str]:
        names = sorted(set(groups))
        for name in names:
            if name not in self._groups:
                raise ValueError(f"groups: unknown group {name}")
        return names

    @staticmethod
    def check_new_password(password: object) -> None:
        """Refuse a password a user chooses when it is below the minimum."""
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")

    @staticmethod
    def _refuse_bootstrap(user_id: str, what: str) -> None:
        if user_id == BOOTSTRAP_ADMIN_ID:
            raise ValueError(f"cannot {what} the bootstrap user {BOOTSTRAP_ADMIN_ID}")

    def _new_setup(self) -> tuple[str, dict]:
        """A fresh setup code and the `setup` object that stores only its digest."""
        code = secrets.token_urlsafe(12)
        setup = {
            "sha256": hashlib.sha256(code.encode()).hexdigest(),
            "expires_at": int(self._clock()) + SETUP_CODE_TTL,
        }
        return code, setup

    def _put(self, rec: dict) -> None:
        """Write the state with `rec` as its user record, then adopt it."""
        users = {**self._users, rec["id"]: rec}
        self._save(users, self._groups)
        self._users = users

    def _create_user(
        self,
        user_id: str,
        *,
        name: str = "",
        admin: bool | None = None,
        groups: Iterable[str] = (),
    ) -> tuple[User, str]:
        """Create a pending user. Return the user and its setup code.

        The groups are `groups`, plus `admins` when `admin` is True; `None`
        lets `groups` decide the role. The record and the code reach the
        file in one write, so a crash leaves either no user or a pending
        user with a code. Private, no cascade. `AccessPolicy.create_user`
        is the public create."""
        group_names = self.check_create_user(user_id, name=name, admin=admin, groups=groups)
        code, setup = self._new_setup()
        rec = {
            "id": user_id,
            "name": name,
            "password_hash": "",
            "groups": group_names,
            "setup": setup,
        }
        # A deleted id starts its next incarnation, so an old snapshot of it
        # never passes `require_current`. Adopted only after the write.
        nxt = self._incarnations[user_id] + 1 if user_id in self._incarnations else 0
        self._put(rec)
        self._incarnations[user_id] = nxt
        return self._to_user(rec), code

    def _replace(self, user_id: str, update: dict) -> None:
        self._put({**self._record(user_id), **update})

    def check_create_user(
        self,
        user_id: str,
        *,
        name: str = "",
        admin: bool | None = None,
        groups: Iterable[str] = (),
    ) -> list[str]:
        """Refuse a user that `_create_user` cannot create. Reads only.

        Else return the sorted group names of the new record: `groups`, plus
        `admins` when `admin` is True. Reads `groups` once. Synchronous."""
        if not isinstance(user_id, str) or not USER_ID_RE.fullmatch(user_id):
            raise ValueError(f"user id must match {USER_ID_RE.pattern}")
        if user_id in self._users:
            raise ValueError(f"user {user_id} already exists")
        if not isinstance(name, str):
            raise ValueError("name must be a string")  # noqa: TRY004 -- a bad value is a ValueError by contract
        group_names = self._check_groups(groups)
        if admin is False and ADMINS_GROUP in group_names:
            raise ValueError(f"admin and groups disagree on {ADMINS_GROUP}")
        if admin is True:
            group_names = sorted({*group_names, ADMINS_GROUP})
        return group_names

    def check_create_group(self, name: str) -> None:
        """Refuse a group that `_create_group` cannot create. Reads only."""
        if not isinstance(name, str) or not GROUP_RE.fullmatch(name):
            raise ValueError(
                "invalid group name: use 1 to 32 lowercase letters, digits, - or _, "
                "starting with a letter"
            )
        if name in self._groups:
            raise ValueError(f"group {name} already exists")

    def check_reset(self, user_id: str) -> None:
        """Refuse a user that `_issue_setup_code` cannot reset. Reads only.

        `ValueError("cannot issue a setup code for the bootstrap user admin")`
        for the bootstrap user, `KeyError(user_id)` for an unknown id, else
        `None`. Synchronous; writes nothing."""
        self._refuse_bootstrap(user_id, "issue a setup code for")
        self._record(user_id)

    def _issue_setup_code(self, user_id: str) -> str:
        """Make the user pending with a new setup code, in one write.

        The old password ends at once, with every session bound to it, and
        the new code replaces any older one. The tokens are not the
        provider's: `AccessPolicy.issue_setup_code` revokes them first.
        Private, no cascade. `AccessPolicy.issue_setup_code` is the public
        reset."""
        self.check_reset(user_id)
        code, setup = self._new_setup()
        self._replace(user_id, {"password_hash": "", "setup": setup})
        return code

    def check_setup_code(self, user_id: str, code: object) -> str | None:
        """The credential state of the user when `code` is its valid setup
        code, else `None`. Never changes state.

        The caller passes the result to `replace_credential` as the expected
        state. One call checks and reads, so no `await` can fall between them
        and swap in the state that a newer code produced (design D2)."""
        # Hash first: one SHA-256 on every path, so the time does not tell
        # an unknown user, an active user, and a wrong code apart.
        raw = code.encode("utf-8", "surrogatepass") if isinstance(code, str) else b""
        digest = hashlib.sha256(raw).hexdigest()
        rec = self._users.get(user_id)
        if (
            not isinstance(code, str)
            or rec is None
            or user_id == BOOTSTRAP_ADMIN_ID
            or rec["password_hash"]
            or "setup" not in rec
        ):
            return None
        setup = rec["setup"]
        if not hmac.compare_digest(digest, setup["sha256"]) or setup["expires_at"] <= self._clock():
            return None
        return self._credential_state(user_id)

    def _credential_state(self, user_id: str) -> str | None:
        """The opaque value `replace_credential` compares. The hash for an
        active user, `"setup:" + sha256` for a pending one, `None` for an
        unknown one. Neither a salted hash nor a code repeats, so a state
        never returns to an earlier value (no ABA)."""
        rec = self._users.get(user_id)
        if rec is None:
            return None
        if rec["password_hash"]:
            return rec["password_hash"]
        return "setup:" + rec.get("setup", {}).get("sha256", "")

    def replace_credential(self, user_id: str, expected_state: str | None, new_hash: str) -> bool:
        """Compare-and-swap of the credential. Synchronous on purpose: no
        other mutator runs between the compare and the write.

        Return `False` when the user is gone or its state is no longer
        `expected_state`; else write `new_hash`, drop `setup`, and return
        `True`. The caller issues the session cookie in the same
        synchronous run, with no `await` after this returns (design D6)."""
        self._refuse_bootstrap(user_id, "replace the credential of")
        if not isinstance(new_hash, str) or not new_hash:
            raise ValueError("new_hash must be a non-empty string")
        state = self._credential_state(user_id)
        if state is None or state != expected_state:
            return False
        rec = {k: v for k, v in self._users[user_id].items() if k != "setup"}
        self._put({**rec, "password_hash": new_hash})
        return True

    def change_groups(
        self,
        user_id: str,
        add: Iterable[str] = (),
        remove: Iterable[str] = (),
    ) -> None:
        """Set the groups of `user_id` to `(current | add) - remove`.

        One synchronous read-and-write, no `await`, so a group the caller
        did not name keeps whatever membership it has now: a stale picker
        cannot undo a concurrent change (design D5). Every error comes
        before the write; an unchanged result writes nothing."""
        rec = self._record(user_id)
        add, remove = set(add), set(remove)
        self._check_groups(add | remove)
        both = sorted(add & remove)
        if both:
            raise ValueError(f"groups: {both[0]} is both added and removed")
        if user_id == BOOTSTRAP_ADMIN_ID and ADMINS_GROUP in remove:
            raise ValueError(_BOOTSTRAP_IN_ADMINS)
        current = set(rec["groups"])
        new = (current | add) - remove
        if new == current:
            return
        self._replace(user_id, {"groups": sorted(new)})

    def set_admin(self, user_id: str, admin: bool) -> None:
        self._refuse_bootstrap(user_id, "change the admin role of")
        if admin:
            self.change_groups(user_id, add=[ADMINS_GROUP])
        else:
            self.change_groups(user_id, remove=[ADMINS_GROUP])

    def set_groups(
        self,
        user_id: str,
        groups: Iterable[str],
        *,
        admin: bool | None = None,
    ) -> None:
        """Replace every group of `user_id` except `admins` with `groups`.

        `admin` decides the membership of `admins`; with `None` it stays,
        and a `groups` list that would change it is refused rather than
        applied as a silent grant or revoke (design D8, R1)."""
        rec = self._record(user_id)
        # Validate every name before the write, so a failed call changes nothing.
        names = set(self._check_groups(groups))
        listed = ADMINS_GROUP in names
        if admin is False and listed:
            raise ValueError(f"admin and groups disagree on {ADMINS_GROUP}")
        current = ADMINS_GROUP in rec["groups"]
        if admin is None and listed != current:
            raise ValueError(f"groups: set admin to change the membership of {ADMINS_GROUP}")
        bit = current if admin is None else bool(admin)
        if user_id == BOOTSTRAP_ADMIN_ID and not bit:
            raise ValueError(_BOOTSTRAP_IN_ADMINS)
        names.discard(ADMINS_GROUP)
        if bit:
            names.add(ADMINS_GROUP)
        self._replace(user_id, {"groups": sorted(names)})

    def remove_member(self, group: str, user_id: str) -> None:
        """Remove `group` from the groups of `user_id`, nothing else.

        Unknown group or user: `KeyError` before any write. A non-member is
        a no-op. A delta through `change_groups`, so two removals cannot
        lose each other, and `admin` never leaves `admins`."""
        if group not in self._groups:
            raise KeyError(group)
        self.change_groups(user_id, remove=[group])

    def change_members(
        self,
        group: str,
        add: Iterable[str] = (),
        remove: Iterable[str] = (),
    ) -> None:
        """Set the members of `group` to `(current | add) - remove`.

        The delta form of `change_groups`, for many users at once: a user the
        caller did not name keeps the membership it has now, so a stale picker
        cannot undo a concurrent change. Every error comes before the one
        write, so a refusal changes nothing; an unchanged result writes
        nothing. `admins` is refused: its members change from the user list,
        where the bootstrap user is guarded."""
        if group not in self._groups:
            raise KeyError(group)
        if group == ADMINS_GROUP:
            raise ValueError(f"change the members of {ADMINS_GROUP} from the user list")
        add, remove = set(add), set(remove)
        both = sorted(add & remove)
        if both:
            raise ValueError(f"members: {both[0]} is both added and removed")
        # A user to add must exist: a missing one is a listed name, so it is
        # a refusal (ValueError), not a missing target. A user to remove that
        # is gone (deleted since the picker rendered) already holds the target
        # state: skip it, so one stale row does not block the rest of the edit.
        for user_id in sorted(add):
            if user_id not in self._users:
                raise ValueError(f"members: unknown user {user_id}")
        users = dict(self._users)
        for user_id in add | (remove & users.keys()):
            rec = users[user_id]
            groups = (set(rec["groups"]) | {group}) if user_id in add else set(rec["groups"]) - {group}
            if groups != set(rec["groups"]):
                users[user_id] = {**rec, "groups": sorted(groups)}
        if users == self._users:
            return
        self._save(users, self._groups)
        self._users = users

    def _create_group(self, name: str) -> None:
        """Private, no cascade. `AccessPolicy.create_group` is the public
        create."""
        self.check_create_group(name)
        groups = [*self._groups, name]
        self._save(self._users, groups)
        self._groups = groups

    def _delete_group(self, name: str) -> None:
        """Delete a group and every membership of it. Private, no cascade:
        `AccessPolicy.delete_group` is the public delete and drops the rules
        after this returns."""
        if name not in self._groups:
            raise KeyError(name)
        if name == ADMINS_GROUP:
            raise ValueError(f"cannot delete the reserved group {ADMINS_GROUP}")
        groups = [g for g in self._groups if g != name]
        users = {
            k: {**rec, "groups": [g for g in rec["groups"] if g != name]}
            for k, rec in self._users.items()
        }
        self._save(users, groups)
        self._users, self._groups = users, groups

    def _delete_user(self, user_id: str) -> None:
        """Private, no cascade. `AccessPolicy.delete_user` is the public delete."""
        self._refuse_bootstrap(user_id, "delete")
        self._record(user_id)
        users = {k: v for k, v in self._users.items() if k != user_id}
        self._save(users, self._groups)
        self._users = users
        # `_incarnations` keeps the id: a re-create must start the next one.
