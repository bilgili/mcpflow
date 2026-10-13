"""Grant rules and every access decision.

`RuleStore` owns `DATA_DIR/rules.json`. `AccessPolicy` owns every allow/deny
decision: the pure `resolve`, the `Reach` of one request (`keys_for`), server
management rights, token authorization, and the user and group cascades. No
caller re-implements any part of a decision; a consumer reads one `Reach`.

The actor of a request is a snapshot the gate took before the handler read
the body. Every write re-reads it in `require_current`, in the same
synchronous section as its first store write, so a revoke or a delete between
the gate and the write refuses the write. Reads keep the snapshot; the next
request resolves the user again at the gate.

The semantics mirror `specs/tla/multi_user_access.tla`: `Resolve`,
`Reachable`, `Candidate`, `ViewRank`, `UserView`, `AdminView`, and `Keys`.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from fastmcp.server.dependencies import get_access_token

from .auth import TokenRecord, TokenStore
from .identity import (
    ADMINS_GROUP,
    BOOTSTRAP_ADMIN_ID,
    GROUP_RE,
    USER_ID_RE,
    IdentityProvider,
    LocalIdentityProvider,
    User,
)
from .registry import Registry, ServerKey, _atomic_write

Level = Literal["global", "server", "tool"]
Effect = Literal["allow", "deny"]
SubjectKind = Literal["user", "group"]
Surface = Literal["mcp", "dashboard"]

ADMIN_REQUIRED: Final[str] = "the admin role is required"
UNKNOWN_ACTOR: Final[str] = "the acting user is unknown"


@dataclass(frozen=True)
class GrantRule:
    id: str
    subject_kind: SubjectKind
    subject: str
    level: Level
    server: str | None  # a server reference
    tool: str | None  # a bare tool name
    effect: Effect
    created_at: datetime


def _check_shape(
    subject_kind: object,
    subject: object,
    level: object,
    server: object,
    tool: object,
    effect: object,
) -> None:
    """Raise `ValueError` naming the first field that breaks the rule shape."""
    if subject_kind not in ("user", "group"):
        raise ValueError("subject_kind must be user or group")
    pattern = USER_ID_RE if subject_kind == "user" else GROUP_RE
    if not isinstance(subject, str) or not pattern.fullmatch(subject):
        raise ValueError(f"subject must match {pattern.pattern}")
    if level not in ("global", "server", "tool"):
        raise ValueError("level must be global, server, or tool")
    if level == "global":
        if server is not None:
            raise ValueError("server must be empty for a global rule")
    else:
        if not isinstance(server, str):
            raise ValueError(f"server is required for a {level} rule")
        try:
            ServerKey.parse(server)
        except ValueError as exc:
            raise ValueError(f"server: {exc}") from None
    if level == "tool":
        if not isinstance(tool, str) or not tool or tool != tool.strip():
            raise ValueError("tool is required for a tool rule")
    elif tool is not None:
        raise ValueError(f"tool must be empty for a {level} rule")
    if effect not in ("allow", "deny"):
        raise ValueError("effect must be allow or deny")


def _rule_from_dict(raw: object) -> GrantRule:
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
        raise ValueError(f"rules.json: malformed rule {raw!r}")  # noqa: TRY004 -- a malformed file is a ValueError by contract
    names = ("subject_kind", "subject", "level", "server", "tool", "effect")
    fields = {k: raw.get(k) for k in names}
    try:
        _check_shape(**fields)
        created_at = datetime.fromisoformat(raw["created_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"rules.json: rule {raw['id']}: {exc}") from None
    return GrantRule(id=raw["id"], created_at=created_at, **fields)


class RuleStore:
    """Grant rules in `rules.json`, version 1. Persist first, adopt second."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._rules: list[GrantRule] = []

    def load(self) -> None:
        if not self._path.exists():
            self._rules = []
            return
        data = json.loads(self._path.read_text())
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ValueError("rules.json: expected an object with version 1")
        raw = data.get("rules", [])
        if not isinstance(raw, list):
            raise ValueError("rules.json: rules must be a list")  # noqa: TRY004 -- a malformed file is a ValueError by contract
        rules = [_rule_from_dict(r) for r in raw]
        if len({r.id for r in rules}) != len(rules):
            raise ValueError("rules.json: duplicate rule id")
        self._rules = rules

    def list(self) -> list[GrantRule]:
        return list(self._rules)

    def add(self, rule: GrantRule) -> None:
        if any(r.id == rule.id for r in self._rules):
            raise ValueError(f"rule {rule.id} already exists")
        self._commit([*self._rules, rule])

    def remove(self, rule_id: str) -> None:
        kept = [r for r in self._rules if r.id != rule_id]
        if len(kept) == len(self._rules):
            raise KeyError(rule_id)
        self._commit(kept)

    def drop_subject(self, kind: SubjectKind, subject: str) -> None:
        self._drop(lambda r: r.subject_kind == kind and r.subject == subject)

    def drop_server(self, ref: str) -> None:
        self._drop(lambda r: r.server == ref)

    def _drop(self, match) -> None:
        kept = [r for r in self._rules if not match(r)]
        if len(kept) != len(self._rules):
            self._commit(kept)

    def _commit(self, candidate: list[GrantRule]) -> None:
        """Write `candidate` through a 0600 temporary file, then adopt it."""
        payload = {
            "version": 1,
            "rules": [
                {
                    "id": r.id,
                    "subject_kind": r.subject_kind,
                    "subject": r.subject,
                    "level": r.level,
                    "server": r.server,
                    "tool": r.tool,
                    "effect": r.effect,
                    "created_at": r.created_at.isoformat(),
                }
                for r in candidate
            ],
        }
        _atomic_write(self._path, payload)
        self._rules = candidate


# --- resolution (D4; TLA+ `Resolve`) ------------------------------------------

_RANK: dict[str, int] = {"global": 1, "server": 2, "tool": 3}


def _applies(rule: GrantRule, user: User) -> bool:
    """TLA+ `Applies`: a user rule names the user; a group rule a member group."""
    if rule.subject_kind == "user":
        return rule.subject == user.id
    return rule.subject in user.groups


def _covers(rule: GrantRule, key: ServerKey, tool: str | None) -> bool:
    """TLA+ `Covers`. A global deny covers every server; a global allow covers
    admin-owned servers only (ruling c). A tool rule never covers `tool=None`."""
    if rule.level == "global":
        return key.owner is None or rule.effect == "deny"
    if rule.level == "server":
        return rule.server == key.ref
    return tool is not None and rule.server == key.ref and rule.tool == tool


def resolve(
    rules: Iterable[GrantRule], user: User, key: ServerKey, tool: str | None
) -> bool:
    """The non-admin decision. Pure: reads only its arguments.

    No matching rule: the owner default. Otherwise keep the most specific
    level, then the user rules when any, and allow only when all keep allow.
    """
    matching = [r for r in rules if _applies(r, user) and _covers(r, key, tool)]
    if not matching:
        return key.owner == user.id
    top = max(_RANK[r.level] for r in matching)
    kept = [r for r in matching if _RANK[r.level] == top]
    own = [r for r in kept if r.subject_kind == "user"]
    return all(r.effect == "allow" for r in (own or kept))


@dataclass(frozen=True)
class Reach:
    """One user, one surface, one request. Only `AccessPolicy.keys_for` builds
    one. `rules` is the snapshot `keys_for` took (C3); the decisions read it
    and nothing else, so one request decides on one rule set."""

    user: User
    surface: Surface
    keys: tuple[ServerKey, ...]
    rules: tuple[GrantRule, ...]

    def allows_tool(self, key: ServerKey, tool: str) -> bool:
        return self._allows(key, tool)

    def allows_server(self, key: ServerKey) -> bool:
        return self._allows(key, None)

    def _allows(self, key: ServerKey, tool: str | None) -> bool:
        # TLA+ `Allowed` / `ServerAllowed`. The global mute is not here: it
        # lives in the child chain and applies to every caller, admin included.
        if key not in self.keys:
            return False
        return self.user.is_admin or resolve(self.rules, self.user, key, tool)


# --- the CallerView (D5; TLA+ `Reachable`, `Candidate`, `ViewRank`) ----------


def _reachable(rules: Iterable[GrantRule], user: User, key: ServerKey) -> bool:
    """TLA+ `Reachable`: an allow for the user names the server, or a global
    allow covers it (admin-owned only). A deny never removes a candidate:
    `resolve` decides on each tool after the view."""
    return any(
        _applies(r, user)
        and r.effect == "allow"
        and (key.owner is None if r.level == "global" else r.server == key.ref)
        for r in rules
    )


def _view_rank(user: User, key: ServerKey) -> tuple[int, str]:
    """TLA+ `ViewRank` then `OwnerKey`: own, then shared (admin-owned), then
    foreign in order of the owner id. A foreign server never beats a shared one."""
    if key.owner == user.id:
        return (0, "")
    if key.owner is None:
        return (1, "")
    return (2, key.owner)


class AccessPolicy:
    def __init__(
        self,
        identity: IdentityProvider,
        rules: RuleStore,
        tokens: TokenStore,
        registry: Registry,
    ) -> None:
        self._identity = identity
        self._rules = rules
        self._tokens = tokens
        self._registry = registry

    def current_user(self) -> User | None:
        """The user of the current MCP request; `None` without one."""
        token = get_access_token()
        return None if token is None else self._identity.resolve(token)

    # --- Reach -----------------------------------------------------------

    def keys_for(self, user: User, surface: Surface) -> Reach:
        """TLA+ `Keys`. The one place a `Reach` is built (C3): the rule list
        is copied once here, and the keys and every decision read that copy."""
        rules = tuple(self._rules.list())
        specs = self._registry.list()
        if user.is_admin:
            # TLA+ `AdminView`: admin-owned only, always approved. The admin
            # dashboard holds every key.
            keys = [s.key for s in specs if surface == "dashboard" or s.owner is None]
        else:
            view = self._user_view(rules, user, specs)
            keys = [
                s.key
                for s in specs
                if s.key in view or (surface == "dashboard" and s.owner == user.id)
            ]
        return Reach(user=user, surface=surface, keys=tuple(keys), rules=rules)

    @staticmethod
    def _user_view(rules: tuple[GrantRule, ...], user: User, specs) -> set[ServerKey]:
        """TLA+ `UserView`: one approved candidate per namespace, by rank."""
        best: dict[str, ServerKey] = {}
        for spec in specs:
            key = spec.key
            if spec.approval != "approved":
                continue  # a pending server is never a candidate
            if key.owner != user.id and not _reachable(rules, user, key):
                continue
            held = best.get(key.namespace)
            if held is None or _view_rank(user, key) < _view_rank(user, held):
                best[key.namespace] = key
        return set(best.values())

    def can_manage(self, user: User, key: ServerKey) -> bool:
        return user.is_admin or key.owner == user.id

    # --- rules -----------------------------------------------------------

    def require_current(self, actor: User) -> None:
        """Refuse a write whose actor snapshot no longer holds.

        Synchronous on purpose: the caller writes after this returns, with
        no `await` between. Reads `self._identity.get_user(actor.id)` once
        and writes nothing; a provider error passes through. The current
        record only takes a right away: it never grants one and never
        changes the branch the snapshot chose. A snapshot of another
        incarnation of the id is an unknown actor: the user it names no
        longer exists. Order: unknown id, other incarnation, lost role."""
        current = self._identity.get_user(actor.id)
        if current is None or current.incarnation != actor.incarnation:
            raise PermissionError(UNKNOWN_ACTOR)
        if actor.is_admin and not current.is_admin:
            raise PermissionError(ADMIN_REQUIRED)

    def _require_admin(self, actor: User) -> None:
        """The write check: the actor still holds, then the snapshot role."""
        self.require_current(actor)
        self._require_admin_role(actor)

    @staticmethod
    def _require_admin_role(actor: User) -> None:
        """The read check: the snapshot role only (reads keep the snapshot)."""
        if not actor.is_admin:
            raise PermissionError(ADMIN_REQUIRED)

    def add_rule(
        self,
        actor: User,
        *,
        subject_kind: str,
        subject: str,
        level: str,
        server: str | None,
        tool: str | None,
        effect: str,
    ) -> GrantRule:
        self._require_admin(actor)
        _check_shape(subject_kind, subject, level, server, tool, effect)
        if subject_kind == "group" and subject == ADMINS_GROUP:
            # Admins skip `resolve` (`keys_for`, `Reach._allows`), so the
            # rule could never apply; refuse it rather than mislead (D6).
            raise ValueError(
                f"subject: members of {ADMINS_GROUP} skip rule resolution; "
                f"a rule on {ADMINS_GROUP} has no effect"
            )
        if subject_kind == "user":
            if self._identity.get_user(subject) is None:
                raise ValueError(f"subject: unknown user {subject}")
        elif subject not in self._identity.list_groups():
            raise ValueError(f"subject: unknown group {subject}")
        if server is not None:
            try:
                self._registry.get(ServerKey.parse(server))
            except KeyError:
                raise ValueError(f"server: unknown server {server}") from None
        rule = GrantRule(
            id="rule_" + secrets.token_hex(6),
            subject_kind=subject_kind,  # type: ignore[arg-type] -- checked above
            subject=subject,
            level=level,  # type: ignore[arg-type]
            server=server,
            tool=tool,
            effect=effect,  # type: ignore[arg-type]
            created_at=datetime.now(UTC),
        )
        self._rules.add(rule)
        return rule

    def remove_rule(self, actor: User, rule_id: str) -> None:
        self._require_admin(actor)
        self._rules.remove(rule_id)

    # --- tokens (D2) -----------------------------------------------------

    def mint_token(
        self, actor: User, name: str, scope: str, user_id: str | None = None
    ) -> tuple[TokenRecord, str]:
        """An admin mints either scope for any user; a non-admin user mints
        `mcp` for themself only. An unknown user raises `ValueError` here,
        because `TokenStore.create` checks only for a non-empty id. The user
        is a body name, not a path target, so it is a 400
        (private-cascade-halves D6)."""
        self.require_current(actor)
        target = actor.id if user_id is None else user_id
        if not actor.is_admin and (scope != "mcp" or target != actor.id):
            raise PermissionError("a non-admin user mints only an mcp token for themself")
        if self._identity.get_user(target) is None:
            raise ValueError(f"user_id: unknown user {target}")
        # The cap exempts by actor, not target: an admin mints past it for
        # itself and for any user (D2).
        return self._tokens.create(name, scope, target, exempt=actor.is_admin)  # type: ignore[arg-type] -- create checks the scope

    def revoke_token(self, actor: User, token_id: str) -> None:
        """A foreign token id answers `KeyError`, the same as an unknown one,
        so a non-admin user cannot tell another user's token exists."""
        self.require_current(actor)
        record = next((r for r in self._tokens.list() if r.id == token_id), None)
        if record is None or not (actor.is_admin or record.user_id == actor.id):
            raise KeyError(token_id)
        self._tokens.revoke(token_id)

    def tokens_for(self, actor: User) -> list[TokenRecord]:
        return self._tokens.list() if actor.is_admin else self._tokens.list_for(actor.id)

    # --- cascades (D8b) --------------------------------------------------

    def local_identity(self) -> LocalIdentityProvider:
        """The Local provider, the one owner of this capability check.

        User and group management and the self-service credential routes
        are a capability of the Local provider only; an external provider
        (Keycloak, P2) owns its directory. Check it before any cascade step,
        so a refusal removes nothing."""
        if not isinstance(self._identity, LocalIdentityProvider):
            # ValueError, not TypeError: an unsupported operation for the
            # caller (400), not a programming error.
            raise ValueError(f"the {self._identity.kind} provider manages its own users")  # noqa: TRY004
        return self._identity

    def delete_user(self, actor: User, user_id: str) -> None:
        """Refuse an owner; then delete the user, revoke tokens, drop rules.

        The identity goes first: the token verifier and the session gate
        re-resolve the user on every request, so from that write on its
        tokens and sessions are refused. A crash at any later step leaves
        only unreachable residue (tokens, rules) and never removes a deny
        from a user who can still act; `create_user` clears that residue
        before an id is reused. The actor check runs before the first store
        write of the cascade, so a refusal leaves all three stores unchanged."""
        self._require_admin(actor)
        local = self.local_identity()
        if user_id == BOOTSTRAP_ADMIN_ID:
            # Refuse before the cascade: `_delete_user` would refuse only
            # after the tokens and the rules of `admin` were gone.
            raise ValueError(f"cannot delete the bootstrap user {BOOTSTRAP_ADMIN_ID}")
        if self._identity.get_user(user_id) is None:
            raise KeyError(user_id)
        owned = [s.key.ref for s in self._registry.list() if s.owner == user_id]
        if owned:
            raise ValueError(f"user {user_id} owns servers {', '.join(owned)}; remove them first")
        local._delete_user(user_id)
        self._tokens.revoke_user(user_id)
        self._rules.drop_subject("user", user_id)

    def delete_group(self, actor: User, name: str) -> None:
        """Delete the group, then drop its rules. A crash between the two
        leaves rules on a group no user is in; `create_group` clears them
        before the name is reused."""
        self._require_admin(actor)
        local = self.local_identity()
        # `_delete_group` refuses an unknown group (KeyError) and `admins`
        # before its write, so a refusal drops no rule.
        local._delete_group(name)
        self._rules.drop_subject("group", name)

    # --- administration --------------------------------------------------
    #
    # The one owner of user, group, and rule administration: the admin check,
    # then the Local-provider check before any change. The provider errors
    # pass through unchanged: ValueError for a bad value or a change D1
    # forbids, KeyError for an unknown target, ValueError for an unknown
    # listed name.

    def create_user(
        self,
        actor: User,
        user_id: str,
        *,
        name: str = "",
        admin: bool | None = None,
        groups: Iterable[str] = (),
    ) -> tuple[User, str]:
        """Create a pending user; return it and its one-time setup code.

        A new id starts clean: after every refusal of the pre-check
        `check_create_user`, clear any tokens and rules an interrupted
        `delete_user` left on the id (D8b), then write the identity. A
        refused create changes no store; a crash never leaves a live user
        with residue."""
        self._require_admin(actor)
        local = self.local_identity()
        groups = tuple(groups)  # read once: the pre-check and the create see the same names
        local.check_create_user(user_id, name=name, admin=admin, groups=groups)
        self._tokens.revoke_user(user_id)
        self._rules.drop_subject("user", user_id)
        return local._create_user(user_id, name=name, admin=admin, groups=groups)

    def issue_setup_code(self, actor: User, user_id: str) -> str:
        """Reset: revoke every token of the user, then make it pending with
        a new setup code.

        Every refusal (actor, provider, bootstrap user, unknown id) comes
        before the first store write, so a refused reset changes no store.
        The revoke goes before the identity write: both bearer gates admit
        the token of a pending user, so an identity-first crash would leave
        a pending user with a live token. A crash between the two writes
        leaves the user in its state from before the reset, with no token of
        the reset start. `delete_user` writes the identity first; both follow
        one rule: a crash never leaves a user more access than before, and
        leaves only unreachable residue. No `await` falls between the steps.

        A self-reset ends the caller's own token too. A request admitted
        before the reset is not stopped and can still write after it."""
        self._require_admin(actor)
        local = self.local_identity()
        local.check_reset(user_id)
        self._tokens.revoke_user(user_id)
        return local._issue_setup_code(user_id)

    def set_admin(self, actor: User, user_id: str, admin: bool) -> None:
        self._require_admin(actor)
        self.local_identity().set_admin(user_id, admin)

    def change_groups(
        self,
        actor: User,
        user_id: str,
        add: Iterable[str] = (),
        remove: Iterable[str] = (),
    ) -> None:
        self._require_admin(actor)
        self.local_identity().change_groups(user_id, add, remove)

    def set_groups(
        self,
        actor: User,
        user_id: str,
        groups: Iterable[str],
        *,
        admin: bool | None = None,
    ) -> None:
        self._require_admin(actor)
        self.local_identity().set_groups(user_id, groups, admin=admin)

    def remove_member(self, actor: User, group: str, user_id: str) -> None:
        self._require_admin(actor)
        self.local_identity().remove_member(group, user_id)

    def change_members(
        self,
        actor: User,
        group: str,
        add: Iterable[str] = (),
        remove: Iterable[str] = (),
    ) -> None:
        self._require_admin(actor)
        self.local_identity().change_members(group, add, remove)

    def create_group(self, actor: User, name: str) -> None:
        """A new group starts clean: after every refusal of the pre-check
        `check_create_group`, clear any rules an interrupted `delete_group`
        left on the name (D8b), then write the identity."""
        self._require_admin(actor)
        local = self.local_identity()
        local.check_create_group(name)
        self._rules.drop_subject("group", name)
        local._create_group(name)

    def list_users(self, actor: User) -> list[User]:
        self._require_admin_role(actor)
        return self._identity.list_users()

    def list_groups(self, actor: User) -> list[str]:
        self._require_admin_role(actor)
        return self._identity.list_groups()

    def list_rules(self, actor: User) -> list[GrantRule]:
        self._require_admin_role(actor)
        return self._rules.list()

    def drop_server_rules(self, key: ServerKey) -> None:
        """Drop every rule that names `key` (D8b). The Supervisor calls it on
        an add, before the registry write, and on a remove, after it, so a
        new server under a reused reference inherits no grant."""
        self._rules.drop_server(key.ref)
