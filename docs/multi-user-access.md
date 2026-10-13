# Multi-user access

MCP Flow serves more than one user from one gateway. Each user sees only the
servers and tools that the admin allows. A user can also propose a server of their
own. The admin approves it before it runs.

This document uses Simplified Technical English (STE). It spells out each
abbreviation on first use. MCP means Model Context Protocol.

## Contents

- [Design in one page](#design-in-one-page)
- [Users, groups, and the admin role](#users-groups-and-the-admin-role)
- [Grant rules](#grant-rules)
- [Tokens](#tokens)
- [The CallerView](#the-callerview)
- [User servers](#user-servers)
- [Residual risks](#residual-risks)
- [Upgrade and downgrade](#upgrade-and-downgrade)
- [Verify the design with TLA+](#verify-the-design-with-tla)
- [Phase plan](#phase-plan)

## Design in one page

One module owns each decision. Every other module asks the owner. No module
repeats a rule.

| Decision | Owner | Module |
|---|---|---|
| Who the user is | `IdentityProvider` | `identity.py` |
| Grant rule storage | `RuleStore` | `policy.py` |
| Every access decision | `AccessPolicy` | `policy.py` |
| Routing of one MCP request | `CallerRouter` | `router.py` |
| Token records | `TokenStore` | `auth.py` |
| Dashboard session and route check | `SessionGate` | `auth.py` |
| Server records and revisions | `Registry` | `registry.py` |
| Child lifecycle and approval | `Supervisor` | `supervisor.py` |

`AccessPolicy.keys_for(user, surface)` is the main seam. It returns one `Reach`
for one user, one surface, and one request. The router, the handshake
instructions, the built-in `mcpflow_*` tools, and the dashboard all read the same
`Reach`. A `Reach` holds the server references that the user may use. It also
holds a snapshot of the grant rules.

The data flow of one MCP request:

```
Authorization: Bearer mcpflow_...
  -> HashedTokenVerifier   token record -> user (unknown user -> 401)
  -> CallerRouter
       AccessPolicy.keys_for(user, "mcp")  -> Reach, computed once
       Supervisor.routed(reach)            -> the running children in the Reach
       child chain: namespace, mute, ...
       Reach.allows_tool / allows_server   -> drop what the policy denies
  -> tool call                             only for a tool that passed every step
```

The gateway resolves the user and the `Reach` on every request. A revoked token,
a deleted user, a role change, a group change, and a rule change all apply to the
next request.

A write checks the acting user once more. `AccessPolicy` and `Supervisor` read
the user again from the identity provider, just before they write. The write
fails when the user no longer exists, when the id now names a new user, or when
the user lost the admin role since the request began. The web pages and `/api`
answer `403` with the text `the acting user is unknown` or `the admin role is
required`. A refused write changes no store. A role that the user gains during the
request grants nothing. A read keeps the snapshot of the request.

A server reference names one server. It is `<namespace>` for an admin-owned
server and `<namespace>@<owner>` for a user-owned server. Every store that keeps
data for one server uses the server reference: `creds/`, `servers/`, and `logs/`.
Thus two users can own the same namespace and keep separate data.

## Users, groups, and the admin role

A user has an id, a name, and a set of groups. The admin role is membership of
the reserved group `admins`.

| Item | Rule |
|---|---|
| User id | Matches `^[a-z0-9][a-z0-9_-]{0,63}$`. The id is the login name. |
| Group name | Matches `^[a-z][a-z0-9_-]{0,31}$`. |
| Group membership | A user names only groups that exist. |
| Admin role | A member of `admins` holds the admin role and manages everything. |

The `IdentityProvider` interface owns users. The Local provider stores users and
groups in `DATA_DIR/users.json`. Only the admin creates users and groups.

The admin manages users, groups, and grant rules on `/security`. The page has
three sections: Users, Groups, and Rules. `GET /users`, `GET /groups`, and
`GET /rules` redirect to the section. Only an admin sees the page.

The group `admins` always exists. No operation deletes it. The Groups section
shows no delete control for it.

To grant the admin role, add the user to `admins`. To revoke it, remove the user
from `admins`. The change takes effect on the next request of the user.

A member of `admins` skips the grant rules. Thus a rule on the group `admins`
has no effect. The Rules section refuses such a rule. A rule on `admins` from an
earlier build stays in `rules.json`. Delete it on the Rules section.

The bootstrap user has the id `admin`. Three rules apply to it:

- The environment owns its password. `ADMIN_PASSWORD_HASH`, or the hash of
  `ADMIN_PASSWORD`, sets the password at every start.
- It always stays in `admins`. Each start puts it back into `admins`.
- No operation deletes it, removes it from `admins`, or changes its password.

### The group picker

The Users section shows the groups of each user as tags. The Groups section
shows the members of each group as tags. Each tag has a × button. The × removes
one user from one group.

A list of more than three shows the count, the first three tags, and a `+N more`
control that opens the rest. The tag `admins` shows a shield. The tag `admins`
of the user `admin` shows a lock and has no ×.

The `⋯` menu of a user row holds **Edit user**, **Reset password**, and
**Delete**. **Edit user** opens the group picker. **Delete** opens a confirm
dialog, and the user is deleted only after you confirm. The picker has these
parts:

- a filter box. Type text to show only the groups that contain the text.
- a list of all groups, sorted by name. The list scrolls when it is long.
- a count of the selected groups.
- **Cancel**. It closes the picker and discards the changes.
- **Save**. It applies the changes.

To make a user an admin, tick `admins` and select **Save**. To create an admin,
tick `admins` in the groups list of **Create user**.

The picker sends only the groups that you change. A group that you do not touch
keeps its current membership. Thus a picker that stays open does not undo a
change that another admin made in the meantime.

For the user `admin`, the box `admins` is locked. The menu of the user `admin`
holds **Edit user** only.

### The Groups menu

Each group except `admins` has a `⋯` menu in the Groups section. The menu holds
**Edit members** and **Delete**. The group `admins` shows `reserved` and has no
menu.

**Edit members** opens a picker with a filter box and a list of all users. It
sends only the members that you change, the same as the group picker. **Delete**
opens a confirm dialog. The delete drops the grant rules of the group and removes
its members from it.

### The users.json file

`users.json` has version 2. A user record holds `id`, `name`, `password_hash`,
and `groups`. A record does not hold the admin role. The group `admins` holds it.

An earlier build wrote version 1. Version 1 kept the role in an `admin` field of
each record. At the first start, the new build migrates the file in one write:

1. It adds the group `admins` when the file does not list it.
2. It adds `admins` to the groups of each user with `admin: true`.
3. It removes the `admin` field from each record.
4. It sets the version to 2.

The migration does not change the role of any user.

A version 1 file can list its own group `admins`. When a member of that group
has `admin: false`, the migration would make that user an admin. The gateway
then refuses to start. The error names the users. Do these steps:

1. Stop the gateway.
2. Rename the group `admins` in `users.json`.
3. Rename the same group in each rule of `rules.json`.
4. Start the gateway.

An admin who deletes a user must first remove the servers of that user. The
delete then revokes the tokens of the user and drops the grant rules for the user.
A user who owns a server cannot be deleted.

Sign-in takes the same time and gives the same error for an unknown user and a
wrong password. The login form takes `user` and `password`. An empty `user` means
`admin`.

### Passwords and setup codes

The admin never chooses the password of a user. The admin creates the user with
the rights, and the user chooses the password.

1. The admin creates the user in the Users section of `/security`, or with
   `POST /api/users`. The user is **pending**: the user has no password. The
   Users section marks the user `pending`.
2. The gateway shows a **setup code** once. `POST /api/users` returns it once in
   the field `setup_code`. The code is single use and ends after 7 days. The
   admin gives the code and the address `/login/setup` to the user.
3. The user opens `/login/setup` and enters the id, the code, and a new password
   twice. The password has at least 8 characters. The user is then signed in.
4. Later, the user changes the password on `/settings`. The page asks for the
   current password. The change keeps the current browser signed in and ends every
   other session of the user.

The admin resets a user with **Reset password** in the Users section, or with
`POST /api/users/{id}/setup-code`. The call returns the new code in `setup_code`.
`POST /api/users` and `PUT /api/users/{id}` refuse a `password` field with `400`.

A reset ends the old password and every session of the user at once. It gives a
new setup code. A reset also revokes every token of the user. A self-reset
revokes the token of the request. An admin can mint a new token for a pending
user.

A reset does not stop a request that the gateway admitted before the reset. That
request can still write after the reset. It can also mint a token for the reset
user. To stop such a request, first remove the user from `admins`: the write-time
check then refuses it. After a reset of a compromised admin, review `/tokens` and
restart the gateway.

The sign-in page gives the same error for a pending user as for a wrong password.
The setup page gives one error for an unknown user, a wrong code, an expired code,
and an active user. These refusals wait 1 second. A password that is too short,
or two passwords that differ, give their own error with no wait.

The user `admin` does not use setup codes. `ADMIN_PASSWORD` or
`ADMIN_PASSWORD_HASH` owns its password, and `/settings` shows a note for it.

## Grant rules

A grant rule lets or stops one subject from using a server or a tool.

| Field | Values |
|---|---|
| Subject | one user, or one group |
| Level | `global`, `server`, or `tool` |
| Target | a server reference for `server` and `tool`; a tool name for `tool` |
| Effect | `allow` or `deny` |

A `server` rule covers every tool, resource, and prompt of one server. A `tool`
rule covers one tool. A `global` deny covers every server. A `global` allow
covers admin-owned servers only. Thus one global allow never exposes a private
server of a user.

### Resolution order

The admin role skips the rules. For every other user, `policy.resolve` decides in
this order:

1. Collect the rules that match the request. If no rule matches, the owner
   default applies: the owner of the server is allowed, and every other user is
   denied.
2. Keep the rules at the most specific level: `tool`, then `server`, then
   `global`.
3. If a user rule is among them, keep the user rules only. A user rule beats a
   group rule.
4. Allow the request only when every kept rule is `allow`. One `deny` wins. Two
   groups that conflict give a deny.

An explicit rule beats the owner default, for `allow` and for `deny`. So an admin
deny stops the owner of a server from using it.

The global mute stays in force for the admin role. The mute lives in the child
chain, not in the rules.

### Worked example

User `alice` belongs to the groups `staff` and `ops`. Alice owns `notes@alice`
and `todo@alice`. The admin owns `gmail` and `calendar`. Bob owns `crm@bob`.

| Id | Subject | Level | Target | Effect |
|---|---|---|---|---|
| R1 | group `staff` | `server` | `gmail` | allow |
| R2 | group `ops` | `server` | `gmail` | deny |
| R3 | user `alice` | `tool` | `gmail`, `list` | allow |
| R4 | user `alice` | `server` | `notes@alice` | deny |
| R5 | group `staff` | `global` | none | allow |

| Request by `alice` | Matching rules | Result | Reason |
|---|---|---|---|
| `gmail`, tool `list` | R1, R2, R3, R5 | allow | The `tool` level wins. R3 is the only rule at that level. |
| `gmail`, tool `send` | R1, R2, R5 | deny | The `server` level wins. R1 allows and R2 denies, so the deny wins. |
| `calendar`, tool `view` | R5 | allow | R5 covers an admin-owned server. |
| `notes@alice`, any tool | R4 | deny | An explicit rule beats the owner default. |
| `todo@alice`, any tool | none | allow | The owner default applies. |
| `crm@bob`, any tool | none | deny | R5 does not cover a user-owned server. The owner default denies. |

A rule decides only for a server that is inside the `Reach`. See "The
CallerView".

## Tokens

An MCP client authenticates to `/mcp` with a bearer token. Each token belongs to
one user. The gateway stores only the SHA-256 digest of a token. SHA means Secure
Hash Algorithm.

A token has one of two scopes:

| Scope | Authenticates |
|---|---|
| `mcp` | `/mcp` |
| `admin` | `/api` and `/mcp` |

The effective scope is `admin` only when the token scope is `admin` and the user
holds the admin role. Every other case gives the effective scope `mcp`. The
application programming interface (API) at `/api` stays admin-only. A non-admin
user uses the dashboard.

| Token scope | User | `/mcp` shows | `mcpflow_*` tools |
|---|---|---|---|
| `admin` | admin role | the admin MCP view | yes |
| `mcp` | admin role | the admin MCP view | no |
| `mcp` or `admin` | no admin role | the CallerView | no |

A non-admin user never sees a `mcpflow_*` tool. The admin MCP view holds
admin-owned servers only. It does not hold the servers of a user.

Who mints a token:

- An admin mints a token of either scope for any user.
- A non-admin user mints an `mcp` token for themself only.
- An admin revokes any token. A user revokes only their own token. A foreign token
  id answers `404`, the same as an unknown id.

`AccessPolicy.mint_token` owns this rule, so every adapter gets it. The file
`tokens.json` holds the tokens of the user `admin`. The file `user_tokens.json`
holds the tokens of every other user.

## The CallerView

The CallerView is the set of servers that one non-admin user sees on `/mcp`.
`AccessPolicy.keys_for` builds it once for each request.

A server is a candidate when it is approved, and when one of these holds:

- The user owns it.
- An `allow` rule for the user covers it.

A pending server is never a candidate.

One namespace gives one server to the view. The rank decides which one:

1. The user's own server.
2. An admin-owned server.
3. A foreign server, in order of the owner id.

A foreign server enters the view only through a `server` or `tool` allow that
names it. A foreign server never takes a namespace from an admin-owned server.

The `surface` argument selects the view:

| Surface | Admin user | Non-admin user |
|---|---|---|
| `mcp` | admin-owned servers | the CallerView |
| `dashboard` | every server | the CallerView, and the servers the user owns in every approval state |

`CallerRouter` is the one provider that the gateway mounts. It gives each
request only the running children in the `Reach` of the caller. The hashed-call
and app-call paths use the same `Reach`. The dashboard of a non-admin user shows
no row for a tool that the policy hides.

### Name collisions

A namespace can contain `_`. Thus `github` with the tool `create_issue` and
`github_create` with the tool `issue` publish one name: `github_create_issue`.

- The registry refuses a user write that creates this relation with an admin-owned
  namespace or with another namespace of the same user. The error reads
  `namespace github_create conflicts with github: a tool name could resolve to both`.
- An admin write is exempt. The marketplace connects a second account under
  `<namespace>_<suffix>`, for example `gmail` and `gmail_work`.
- The router is the backstop. It drops a published name that two routed tools
  share, in the list and in the call. It writes one warning for each name.
- The router applies the same rule to prompt names, resource URIs, and resource
  template URIs. It drops a name that two servers publish from the list, and it
  answers a get of that name as unknown. It writes one warning for each name. It
  refuses the colliding names only, not the whole server.
- A prompt name must start with `<namespace>_`. A resource URI or a template URI
  must start with `<scheme>://<namespace>/`. The router lists no component that
  fails this test.
- A muted component, or a component that the rules deny, does not count in a
  collision. It never hides a visible component.
- A server can fail during a request. The router then refuses each tool name,
  prompt name, resource URI, and template URI that the failed server may own. A
  failed server may own a name that starts with its `<namespace>_` or
  `<scheme>://<namespace>/`. The router writes one warning that names the failed
  server. The name returns when the provider answers again.
- While a server fails, the router also hides the names that other servers
  publish under that prefix. A hashed call or an app call gets the answer unknown
  when any provider fails during that call.

### Dashboard routes

`SessionGate` denies every dashboard route to a non-admin user by default. Only
the routes in `USER_ROUTES` (in `web.py`) pass. These are the dashboard, the
tool tree at `/tools/tree`, the server pages of the user, the add-server form,
the token pages, and the settings page. Every other route answers `403`. A route
that a later change adds stays admin-only until an author lists it.

A server route answers `404` when the user cannot manage that server. So a user
cannot tell a foreign server from a missing one.

The session cookie names the user. A change of the password of a user ends every
session of that user.

`SessionGate` also rejects a cross-site `POST`. It compares the host of the
`Origin` header with the `Host` header. The check covers `/login` and
`/login/setup`. A failed check answers `403` with the text `cross-origin request
rejected`, sets no cookie, and does not run the route. The paths `/mcp` and
`/api/` take a bearer token, not a cookie, so the check skips them. The prefix
match uses whole path segments: `/mcp/x` passes the skip and `/mcpfoo` does not.

An in-page request with the header `HX-Request: true` and no valid session gets
`401` and the header `HX-Redirect: /login?next=<page path>`. The htmx library
then loads the full sign-in page. A plain `GET` with no session gets `303` to
`/login`.

## User servers

A non-admin user proposes a server. The admin approves it. Only then does the
server run.

### The flow

1. The user submits the add-server form with the kind `python`, `npm`, or
   `remote`. The registry stores the server in `user_servers.json`. The owner is
   the user. The approval state is `pending`.
2. A pending server stays `stopped`. It is not in any `Reach`. A pending `remote`
   server opens no connection, so MCP Flow sends no request to its Uniform
   Resource Locator (URL).
3. The admin opens `/approvals`. The page shows the command, the URL, the names
   of the `env` keys, and the revision of each pending server.
4. The admin selects approve. The form posts the revision that the admin read.
5. `Supervisor.approve` compares that revision with the revision of the stored
   server. A mismatch raises `RevisionConflict`. The API answers `409`. The page
   shows the text `the server changed since you opened this page`. The server stays
   pending.
6. A match writes `approved_revision` and starts the child when `enabled` is true.
7. Reject removes the server.

The approval state is derived. A server is `approved` when `approved_revision`
equals the current revision. Otherwise it is `pending`. No record stores an
approval flag.

### The revision

The revision is the SHA-256 digest of these fields of the server record:
`kind`, `package`, `args`, `url`, `transport`, `headers`, `command`, `env`, and
`source`. These fields decide which code runs and where it connects.

An edit of one of these fields changes the revision. The server then returns to
`pending`, and the supervisor stops it. This rule applies to every editor,
including the admin. An edit of `description`, `enabled`, `cache_ttl`, or the
mute state keeps the approval.

Every start path goes through `Supervisor._begin_start`. It reads the stored
record, never an incoming spec. A start that races with an edit never publishes
an un-approved revision.

### Who may write a server

An admin writes every server. A non-admin user writes only the servers that the
user owns. A non-admin user who writes to the server of another user gets `404`,
the same answer as for a missing server.

Only an admin approves a server, mutes a tool or a namespace, writes inline
source files, runs an action, or finishes an OAuth flow. An owner who is not an
admin gets `403` for these writes on the own server.

`Supervisor` takes the acting user into each server write. It checks the user
again at write time, as "Design in one page" states. An admin who loses the role
during a request gets `403`. The same user keeps the rights of an owner on an
own server, so a retry works.

### Pinning

The registry refuses a user-owned server that does not name immutable code. The
error names the field. Admin-owned servers are exempt.

| Kind | Accepted form | Refused |
|---|---|---|
| `npm` | `package` is `name@X.Y.Z` or `@scope/name@X.Y.Z`. An exact pre-release or build suffix is allowed, for example `1.2.3-beta.1`. | a range, a tag, `latest`, no version |
| `python` | `package` is `name==` and one exact PEP 440 version, for example `1.2`, `1.2.3`, `1.2.3rc1`, or `1.2.3.post1` | `>=`, `~=`, `*`, `==1.2.*`, no version |
| `python` with `source` | `git+https://host/owner/repo@<sha>` | a branch, a tag, a short SHA, an `https` archive, a local path |
| `npm` with `source` | `github:owner/repo#<sha>` or `git+https://host/owner/repo#<sha>` | the same as above |
| `custom` | none | every `custom` server |
| `remote` | not applicable | nothing; the approval binds the URL and the headers |

Each `<sha>` is a full 40-character commit hash. With a `source`, `package` names
the executable. A `custom` command names a host executable, and no digest of the
record covers its content. So no approval can bind it.

The registry also refuses an `env` key that changes which code the child loads.
It compares the key without regard to case. It refuses these exact names:

- `PATH`
- `HOME`
- `NPX`
- `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`
- `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`

It also refuses each key that starts with one of these prefixes:

- `LD_`
- `DYLD_`
- `PYTHON`
- `NODE_`
- `NPM_CONFIG_`
- `UV_`
- `PIP_`
- `GIT_`
- `XDG_`
- `BUN_`

These keys can load a library, preload a module, or redirect the package index.
A proxy key plus a trust key could serve other bytes for a pinned version.

With a `source`, `package` must be a bare name. A value such as `--with` or
`-c` would become an option of `uvx` or `npx`, so the registry refuses it.
The marketplace and the OAuth routes stay admin-only.

## Residual risks

Approval and pinning reduce the risk. They do not remove it. Read this list
before you approve a user server.

- **Approved code has the gateway's access.** It runs as the gateway process with
  the gateway environment. It can read `DATA_DIR`. That directory holds every
  stored credential, every token digest, and every password hash.
- **Transitive dependencies are not pinned.** Pinning binds the top-level
  package only. `uvx` and `npx` resolve the dependencies at each start. A new
  release of a dependency can run under an approved revision. A Python package
  version can also gain a new wheel file after the approval.
- **There is no isolation at the operating-system level.** A child is an
  ordinary process of the gateway user. MCP Flow adds no sandbox.
- **A remote URL can reach the local network.** The gateway connects to the URL
  that a user proposes. The URL can name a host on the local area network (LAN) or
  on the gateway machine. For this reason approval is required. Read the URL and
  the header names before you approve.
- **An open session keeps its instructions.** The instructions of an MCP session
  are fixed at the handshake. A revoked grant leaves that text in the client. The
  text grants no call. The gateway authorizes every call again.

The `/approvals` page states the first two risks.

## Upgrade and downgrade

### Upgrade

An upgrade needs no manual step. At the first start of the new build:

1. The Local provider finds no `users.json`. It creates the group `admins` and
   the user `admin` in it, with the password hash from the environment. A
   version 1 `users.json` migrates to version 2 (see
   [The users.json file](#the-usersjson-file)).
2. The token store gives every token without a user to `admin`.
3. The registry loads `servers.json` as admin-owned servers.
4. The rule store finds no `rules.json`. No grant rule exists.

The build adds four files under `DATA_DIR`. It creates `users.json` at the first
start. It creates each other file when the first record needs it.

| File | Content |
|---|---|
| `users.json` | users and groups |
| `user_servers.json` | user-owned servers, with `owner` and `approved_revision` |
| `user_tokens.json` | tokens of every user except `admin` |
| `rules.json` | grant rules |

After the upgrade, every existing server starts as before. An old `mcp` token
lists the same tools as before. An old `admin` token also lists the `mcpflow_*`
tools, as before.

The session cookie changes format. Every browser must sign in once. Sign in with
the user `admin`, or leave the user empty, and use the same password.

### Downgrade

A downgrade fails closed. The earlier build reads `servers.json` and
`tokens.json` only. It ignores `users.json`, `user_servers.json`,
`user_tokens.json`, and `rules.json`. So the earlier build:

- starts no pending or approved user server;
- accepts no token of a user other than `admin`;
- sees no second server under one namespace;
- uses `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH` as before.

A build that reads `users.json` version 1 refuses a version 2 file. It stops
with the error "expected an object with version 1". To roll back to such a
build, do these steps:

1. Stop the gateway.
2. In `users.json`, set `version` to 1.
3. Start the earlier build.

The earlier build then reads every user except `admin` as a non-admin. It reads
`admins` as a plain group. Thus a rollback removes the admin role, and never
grants it.

The new files stay in `DATA_DIR`. A later upgrade finds them again. A downgrade
removes access. It never opens access.

## Verify the design with TLA+

The design has a formal model in TLA+ (Temporal Logic of Actions). The TLA+
model checker (TLC) explores every reachable state. The model and its configs are
under `specs/tla/`. That directory exists on the development branch `ci` only. It
also holds the models of the later changes, for example `admins_group.tla` and
`reresolve_actor.tla`.

Run the check from the repository root:

```sh
specs/tla/multi_user_access_check.sh
```

The script needs the `tlc` command on `PATH`. It looks in `~/.local/bin`.

### The two modules

| Module | Models |
|---|---|
| `multi_user_access.tla` | The policy: rule resolution, the CallerView, the surfaces, the mute, and name collisions |
| `multi_user_access_lifecycle.tla` | The approval race, the revision, the two-step start, and the store keys |

### Expected outcome of each config

A positive config must pass. TLC reports `No error has been found`. A negative
config models a rejected design. It must fail with the invariant that the table
names. If a negative config passes, the script fails.

| Config | Outcome |
|---|---|
| `multi_user_access.cfg` | pass |
| `multi_user_access_rules3.cfg` | pass; takes about 1.5 hours |
| `multi_user_access_lifecycle.cfg` | pass; checks the liveness property `ApprovedEventuallyRuns` |

| Negative config suffix | Rejected design | Invariant that fails |
|---|---|---|
| `hashpath`, `apppath` | the hash or app path skips the decision | `NoMcpLeak` |
| `dashlist` | `Supervisor.tools()` lists every child | `NoDashLeak` |
| `instructions` | the handshake holds every child | `NoInstructionsLeak` |
| `groupbeatsuser` | a group rule beats a user rule | `UserBeatsGroup` |
| `allowwins` | allow beats deny among equals | `ConflictingGroupsDeny` |
| `ownerfirst` | the owner allow beats a deny | `OwnerAllowNeverBeatsDeny` |
| `globalleak` | a global allow covers user servers | `GlobalAllowNeverLeaksPrivate` |
| `noapproval` | a start skips approval | `PendingNeverRunning` |
| `pendingreach` | a pending server is reachable | `PendingNeverReachable` |
| `editkeeps` | an edit keeps the approval | `ApprovalCoversCurrentSpec` |
| `twoinview` | no tie-break in the view | `ViewUnique` |
| `tieonly` | no tie-break, router refusal on | `OwnerSeesOwnStrict` |
| `twoinview_call` | no tie-break and no router refusal | `OneServerPerName` |
| `foreignfirst` | a foreign server ranks above an admin-owned one | `ForeignNeverShadowsShared` |
| `adminprivate` | the admin view holds user servers | `AdminViewExcludesPrivate` |
| `adminlisttools` | the admin tools read the dashboard surface | `AdminMcpExcludesPrivate` |
| `ambiguousname` | the router serves a shared name | `OneServerPerToolName` |
| `adminmute` | the admin bypass skips the mute | `MutedHiddenForAll` |
| `stale` | decisions fixed at the handshake | `NoMcpLeak` |
| `lifecycle_noreview` | `approve` takes no revision | `RunningSpecWasReviewed` |
| `lifecycle_nocancel` | an edit leaves the start task alone | `PublishedImpliesApproved` |
| `lifecycle_nskeyed` | the stores key by namespace | `OpTouchesOnlyOwnPaths` |

The script prefixes each suffix with `multi_user_access_`.

### Skip the long check

`SKIP_RULES3=1` skips the `rules3` config. Use it for local iteration only.

```sh
SKIP_RULES3=1 specs/tla/multi_user_access_check.sh
```

Never use `SKIP_RULES3=1` for a release gate. A release gate runs every config.

## Phase plan

This change is phase 1 (P1). It adds the Local identity provider, grant rules,
and user servers. The later phases use the same `IdentityProvider` interface.

| Phase | Adds | What stays the same |
|---|---|---|
| P2 | Keycloak with OpenID Connect (OIDC). A `KeycloakIdentityProvider` builds the user from the claims of a JSON Web Token. | `keys_for`, the router, and the rules |
| P3 | Identity pass-through. The router adds the user id to a call for a child marked user-aware. | the policy |
| P4 | Per-user credentials. One child instance for each user and server. The credential path becomes `creds/<ref>/<user>/`. | the `Reach` |
