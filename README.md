<p align="center">
  <img src="src/mcpflow/static/logo.svg" alt="MCP Flow" width="320">
</p>

<h1 align="center">MCP Flow</h1>

<p align="center">One gateway. Many Model Context Protocol (MCP) servers. One address for every agent.</p>

MCP Flow is one process that serves three things on one port. It serves the
MCP gateway at `/mcp`. It serves an admin web user interface (UI). It serves a
health endpoint at `/health`. The Python package and the console command keep
the name `mcpflow`.

The gateway runs child MCP servers as subprocesses. It also proxies remote MCP
servers. A failed child does not stop the gateway or another child. A change to
a child takes effect without a process restart.

## How it works

```
  agent ──┐                          ┌── uvx  <python package>   (namespace a)
  agent ──┼── Bearer token ──► /mcp ─┼── npx  <npm package>      (namespace b)
  agent ──┘        MCP Flow          ├── https://remote/mcp      (namespace c)
                      │              └── mcpflow_*  built-in admin tools
             /login  /  /marketplace  /tokens  /api
```

- An agent connects to `/mcp` with one bearer token. The gateway publishes every visible
  tool of every running child as `{namespace}_{tool}`. A muted tool stays hidden.
- The admin adds, edits, mutes, and restarts children in the web UI, over the
  Representational State Transfer (REST) application programming interface
  (API) at `/api`, or with the built-in `mcpflow_*` MCP tools.
- The gateway keeps its persistent state under one data directory. See "Files under
  `DATA_DIR`".

## Screens

Select a picture to open it at full size.

<table>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/01-dashboard.png"><img src="docs/screenshots/thumbs/01-dashboard.png" alt="The dashboard with one group per server"></a>
      <br><b>Dashboard.</b> One collapsible group per registered server.
    </td>
    <td width="50%">
      <a href="docs/screenshots/02-dashboard-group-expanded.png"><img src="docs/screenshots/thumbs/02-dashboard-group-expanded.png" alt="An expanded group showing the server row and the tool table"></a>
      <br><b>An expanded group.</b> The run command, then every tool it publishes.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/03-server-window.png"><img src="docs/screenshots/thumbs/03-server-window.png" alt="The server window open over the dashboard"></a>
      <br><b>Server window.</b> Edit, restart, disable, remove, and read the log.
    </td>
    <td width="50%">
      <a href="docs/screenshots/04-add-server.png"><img src="docs/screenshots/thumbs/04-add-server.png" alt="The add-server window on the Python tab"></a>
      <br><b>Add a server.</b> By Python package, by npm package, or by URL.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/05-add-server-json.png"><img src="docs/screenshots/thumbs/05-add-server-json.png" alt="The add-server window on the JSON tab"></a>
      <br><b>Paste a config.</b> An <code>mcpServers</code> block from another client fills the fields.
    </td>
    <td width="50%">
      <a href="docs/screenshots/06-marketplace.png"><img src="docs/screenshots/thumbs/06-marketplace.png" alt="The marketplace grid"></a>
      <br><b>Marketplace.</b> Ready-made entries; a connected one shows its namespace.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/07-marketplace-detail.png"><img src="docs/screenshots/thumbs/07-marketplace-detail.png" alt="A marketplace entry detail"></a>
      <br><b>Marketplace entry.</b> The record it writes and the command it runs as.
    </td>
    <td width="50%">
      <a href="docs/screenshots/08-tokens.png"><img src="docs/screenshots/thumbs/08-tokens.png" alt="The tokens page"></a>
      <br><b>Tokens.</b> Create a bearer token and copy the client config.
    </td>
  </tr>
</table>

### How the dashboard loads

`GET /` returns a page shell with no tools. The page then loads the tool tree
from `/tools/tree`. The tree reads one stored tool list for each running child
and waits for no child. Thus a slow child never delays the page.

The gateway keeps the tool list of each running child. When a list is older than
10 seconds, a load of the tree or a control answer starts a background refresh.
The refresh also marks a dead `running` child as `failed`. While a child starts
or a refresh runs, the tree polls every 3 seconds. `GET /api/tools` and
`mcpflow_list_tools` read the same stored lists.

When the session has ended, a request from the page gets `401` with an
`HX-Redirect` header to `/login?next=<page>`. The htmx library then loads the
full sign-in page, not a sign-in form inside the tool tree. A plain browser
`GET` gets `303` to `/login`.

## Contents

- [Screens](#screens)
- [Install](#install)
- [Set the admin password](#set-the-admin-password)
- [Run the server](#run-the-server)
- [Run with Docker](#run-with-docker)
- [Environment variables](#environment-variables)
- [Files under `DATA_DIR`](#files-under-data_dir)
- [Add a server](#add-a-server)
- [Import from mcpmarket](#import-from-mcpmarket)
- [API tokens](#api-tokens)
- [Multiple users](#multiple-users)
- [Connect an agent](#connect-an-agent)
- [Admin API](#admin-api)
- [Admin MCP tools](#admin-mcp-tools)
- [Secrets](#secrets)
- [Inline source servers](#inline-source-servers)
- [Development](#development)
- [License](#license)

## Install

Install the package with pip. The package needs Python 3.12 or newer. The package
needs `fastmcp` 4.1.0 or newer, and older than 5. Pip installs it for you. The
source is at `https://github.com/bilgili/mcpflow`.

```sh
pip install mcpflow
```

## Set the admin password

The process needs an admin password. Create a password hash first.

```sh
mcpflow hash-password
```

The command prints one line that starts with `pbkdf2_sha256$`. Set the line as
`ADMIN_PASSWORD_HASH`. You can also set the clear-text `ADMIN_PASSWORD` instead,
but the hash is safer.

`ADMIN_PASSWORD_HASH` or `ADMIN_PASSWORD` owns the password of the user `admin`.
The process sets that password from the environment at every start. To change it,
change the environment variable and restart. See [Multiple users](#multiple-users).

## Run the server

Start the gateway with `serve`. The flags override the environment variables.

```sh
export ADMIN_PASSWORD_HASH='pbkdf2_sha256$...'
mcpflow serve --host 127.0.0.1 --port 8000 --data-dir ./data
```

Open `http://127.0.0.1:8000/login`. Enter the user `admin` and the admin password.
An empty user name means `admin`.

## Run with Docker

Copy the example environment file and set the values.

```sh
cp .env.example .env
# set ADMIN_PASSWORD_HASH and SECRET_KEY in .env
docker compose up -d
```

The compose file builds the image, maps port `8000`, and mounts a named volume
at `/data`. Open `http://localhost:8000/login`. Leave the user name empty, or enter `admin`.

The named volume is `mcpflow-data`.

To build the image from a local wheel, run `make docker-build-local`. The
command builds the wheel and passes it to Docker through a named build context.

## Environment variables

| Name | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `./data` (Docker: `/data`) | registry, tokens, logs, caches |
| `HOST` | `127.0.0.1` (Docker: `0.0.0.0`) | bind address |
| `PORT` | `8000` | bind port |
| `ADMIN_PASSWORD` | unset | clear-text password of the user `admin`; hashed in memory at start |
| `ADMIN_PASSWORD_HASH` | unset | password hash of the user `admin`; output of `mcpflow hash-password`; wins over `ADMIN_PASSWORD` |
| `SECRET_KEY` | unset | cookie signing key; else `DATA_DIR/secret_key` |
| `COOKIE_SECURE` | `0` | set `1` behind HTTPS |
| `SESSION_TTL_SECONDS` | `604800` | session lifetime |
| `CHILD_START_TIMEOUT` | `60` | probe timeout in seconds |
| `CHILD_CACHE_TTL` | `300` | seconds a child component list serves lookups by name |
| `LOG_LEVEL` | `INFO` | process log level |
| `PUBLIC_URL` | unset | externally reachable base URL; else the request host |
| `MAX_USER_SERVERS` | `20` | maximum count of servers that one non-admin user owns; `0` allows none; the admin has no limit |
| `MAX_USER_TOKENS` | `10` | maximum count of tokens that one non-admin user holds; `0` allows none; an admin mint has no limit |
| `UV_CACHE_DIR` | Docker: `/data/cache/uv` | uvx cache |
| `npm_config_cache` | Docker: `/data/cache/npm` | npx cache |

A child's `cache_ttl` in `servers.json` or the form overrides it; `0` disables the cache for that child.

A lower `MAX_USER_SERVERS` or `MAX_USER_TOKENS` removes no existing server or token. The process starts with the existing files. The next add or mint of that user fails until the count is below the limit. A token that an admin mints for a user counts toward the limit of that user. A value that is not an integer, or that is below `0`, stops the start with an error.

Behind a reverse proxy, forward the original `Host` header, with the public
port when it is not 80 or 443. The gateway checks the `Origin` header of every
form `POST`, sign-in and setup sign-in included. When `Origin` is present and
its host differs from `Host`, the gateway answers `403 cross-origin request
rejected`. An `Origin` of `null` also fails. A `POST` with no `Origin` passes.

The check skips `/mcp` and `/api/`, because they take a bearer token and no
cookie. The match uses whole path segments. `/mcp/x` is skipped. `/mcpfoo` is
not.

## Files under `DATA_DIR`

The process keeps all state under one data directory.

- `servers.json`: the persisted list of admin-owned child servers.
- `user_servers.json`: the child servers that users own, with the owner and the approved revision. See [Multiple users](#multiple-users).
- `tokens.json`: the API tokens of the user `admin`. The file holds only the SHA-256 digest of each token.
- `user_tokens.json`: the API tokens of every other user. The file holds only the SHA-256 digest of each token.
- `users.json`: the users and the groups. The admin role is membership of the group `admins`.
- `rules.json`: the grant rules.
- `secret_key`: the cookie signing key. The process creates it on first start with mode `0600`.
- `logs/{ref}.log`: the stderr of one child. The process truncates it on each start. The process deletes it when the secrets of the child change and when the child is removed.
- `servers/{ref}/`: the inline source files of one child (see Inline source servers). Directories are mode `0700`, files `0600`.
- `creds/{ref}/`: `client.json` and `token.json` for an OAuth child. Files are mode `0600`.
- `cache/uv` and `cache/npm`: the package caches in Docker.

`{ref}` is the server reference. For an admin-owned server it is the namespace.
For a user-owned server it is `<namespace>@<owner>`.

## Add a server

Open `/` and select **Add server**. The add window opens over the dashboard
and has three tabs.

- **Python**: run a Python MCP server with `uvx <package>`. Enter the package and arguments.
- **npm**: run a Node MCP server with `npx -y <package>`. Enter the package and arguments.
- **JSON**: paste a raw MCP config block. The form reads a `mcpServers` object or a bare name map.

The add form supports two more kinds through import. A `remote` server proxies
an HTTP or SSE URL. A `custom` server runs any command.

### Source: run a package from a git repo or a local directory

The Python and npm tabs accept an optional **Source**. It names where to
install the package from: a git URL, a `github:` shorthand, or an absolute
directory path. It must start with `git+https://`, `https://`, `github:`, or
`/`. Only the Python and npm kinds accept a source.

With a source, the gateway runs `uvx --from <source> <package>` or
`npx -y --package=<source> <bin>`. On the npm tab, `Package` is then the bin
name, not the npm package name.

```
# Python from a git repo
source:  git+https://github.com/owner/repo
package: my-tool

# npm from a github shorthand
source:  github:owner/repo
package: my-bin
```

A source may embed a credential for a private repo, for example
`git+https://oauth2:<token>@gitlab.example/owner/repo`. The gateway stores the
raw URL in `servers.json` (mode `0600`). The dashboard, the server window,
every REST API response, and every admin MCP tool result show the redacted form
`git+https://***@gitlab.example/owner/repo`. See Secrets.

## Import from mcpmarket

The **mcpmarket** tab posts a listing URL. The importer fetches the page and
pre-fills the add form from the first server that it finds. The admin always
confirms before the registry changes.

The importer accepts only `https` URLs on the allowed hosts `mcpmarket.com`,
`www.mcpmarket.com`, `github.com`, and `raw.githubusercontent.com`. It does not
follow redirects.

The import can fail. mcpmarket.com can answer `429`. The page can carry no MCP
config. On a failure the UI shows the error and a JSON paste field. Paste the
server config and confirm.

## API tokens

An MCP client authenticates to `/mcp` with a bearer token. Open `/tokens` to
manage the tokens.

- Enter a name and a scope, then select **Create token**. The page shows the
  token once. It starts with `mcpflow_`. Copy it now. The server stores only the
  SHA-256 digest.
- Select **revoke** to delete a token. The next request with that token fails.

A token has one scope. An `mcp` token authenticates `/mcp` only. An `admin`
token authenticates `/api` and `/mcp`. An `admin` session on `/mcp` also sees
the built-in admin tools (see Admin MCP tools below). The scope selector
defaults to `mcp`. A token belongs to one user. An `admin` token works only while
its user holds the admin role.

Send the token in the `Authorization` header.

```
Authorization: Bearer mcpflow_<token>
```

The gateway publishes every tool of a running child as `{namespace}_{tool}`.

## Multiple users

The gateway serves more than one user. The admin creates users and groups, and
writes grant rules that allow or deny a server or a tool. A user sees only the
servers and tools that the rules allow, plus the servers that the user owns. A
non-admin user never sees a `mcpflow_*` tool.

- The user `admin` always exists and always holds the admin role. The environment
  owns its password. See [Set the admin password](#set-the-admin-password).
- Each token belongs to one user. A non-admin user creates an `mcp` token for
  themself on `/tokens`. See [API tokens](#api-tokens).
- A non-admin user proposes a server on the dashboard. The server stays pending
  until the admin approves it on `/approvals`. The registry accepts only pinned
  code from a user: an exact package version, or a git source with a full commit
  hash.
- `/api` and the `mcpflow_*` tools stay admin-only.
- The admin manages users, groups, and grant rules on `/security`. The page has
  three sections: Users, Groups, and Rules. `/users`, `/groups`, and `/rules`
  redirect to it.
- A group list shows as tags. The × on a tag removes one user from one group. A
  list of more than three shows the first three and a `+N more` control. **Edit
  user** and **Edit members** open a picker. **Delete** of a user or a group
  asks for confirmation.
- The admin never sets a password. A new user is **pending** until the user
  enters a one-time setup code on `/login/setup` and chooses a password. The
  code ends after 7 days. A user changes the password on `/settings`.
- **Reset password** makes the user pending and gives a new setup code. It ends
  every session and revokes every token of that user. `POST /api/users` and
  `POST /api/users/{id}/setup-code` return the code once, in `setup_code`.
- An admin writes every server. A non-admin user writes only the servers that
  the user owns. Only an admin approves a server or mutes a tool.
- The gateway checks the acting user again just before each write. A write
  gets `403` when the user was deleted, or lost the admin role, since the
  request began. A refused write changes nothing.
- An approved user server runs as the gateway process and can read `DATA_DIR`. Read
  the residual risks before you approve one.
- An upgrade needs no manual step. It signs every browser out once. A downgrade
  fails closed.
- For how the gateway masks secrets, see [Secrets](#secrets).

The full design, the resolution order of the rules, the pinned forms, the risks,
and the upgrade notes are in [docs/multi-user-access.md](docs/multi-user-access.md).

## Connect an agent

Every client needs the same two facts: the URL of the gateway and one bearer
token. MCP Flow speaks streamable HTTP at `/mcp`. It is one server to the
client, however many children it runs behind that address.

Create a token at `/tokens` first. That page prints the two blocks below with
your real host and token already filled in, so copy from there rather than
retyping.

```
URL     https://mcp.example/mcp
Header  Authorization: Bearer mcpflow_<token>
```

### Claude Code

Run one command. It writes the server into the Claude Code config for you.

```sh
claude mcp add --transport http mcpflow https://mcp.example/mcp --header "Authorization: Bearer mcpflow_<token>"
```

Check it with `claude mcp list`. To share the server with a repository instead
of your user account, add `--scope project`; Claude Code then writes `.mcp.json`
beside your code, so use a token you are willing to commit, or none at all.

### Any client that reads an `mcpServers` block

Most clients take the same JSON. Paste this into the client's MCP config file:

```json
{
  "mcpServers": {
    "mcpflow": {
      "type": "http",
      "url": "https://mcp.example/mcp",
      "headers": {
        "Authorization": "Bearer mcpflow_<token>"
      }
    }
  }
}
```

Where that file lives differs by client:

| Client | Config file |
| --- | --- |
| Claude Code | `~/.claude.json`, or `.mcp.json` in a project |
| Cursor | `~/.cursor/mcp.json`, or `.cursor/mcp.json` in a project |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Claude Desktop | `claude_desktop_config.json` in the app's support directory |

Two clients differ from the block above. **VS Code** names the top-level key
`servers`, not `mcpServers`, and reads `.vscode/mcp.json` in a workspace.
**Codex CLI** keeps its servers in `~/.codex/config.toml` as
`[mcp_servers.mcpflow]` rather than in JSON.

These formats move. If a client rejects the block, check that client's own
documentation for the current key names; the URL and the `Authorization` header
are the parts that come from MCP Flow.

### Check the connection

Ask the agent to list its tools. Every tool MCP Flow publishes carries its
namespace as a prefix, so a `time` server appears as `time_get_current_time`.
If the agent sees nothing, confirm the child reports `running` on the dashboard
and that the namespace is not muted.

An `admin` token additionally exposes the built-in `mcpflow_*` tools, so the
agent can add and restart servers itself. See "Admin MCP tools" below.

## Admin API

The gateway serves a JSON REST API under `/api`. A script manages the same
servers, tools, tokens, users, groups, grant rules, and approvals as the HTML
pages. Every route needs an `admin`
token in the `Authorization` header. The session cookie does not authenticate
`/api`. An `mcp` token authenticates `/mcp` only; an `admin` token
authenticates `/api` and `/mcp`. Create an `admin` token on `/tokens`.

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/api/servers` | — | list the children |
| POST | `/api/servers` | `ServerSpec` fields | add a child, `201` |
| GET | `/api/servers/{ns}` | — | one child |
| PUT | `/api/servers/{ns}` | `ServerSpec` fields | replace a child |
| DELETE | `/api/servers/{ns}` | — | remove a child, `204` |
| POST | `/api/servers/{ns}/enable` | — | enable a child |
| POST | `/api/servers/{ns}/disable` | — | disable a child |
| POST | `/api/servers/{ns}/restart` | — | restart a child |
| GET | `/api/servers/{ns}/log?lines=N` | — | the log tail as text |
| GET | `/api/tools` | — | the tool list |
| PUT | `/api/visibility/root` | `{"muted": bool}` | mute or show all tools |
| PUT | `/api/visibility/namespaces/{ns}` | `{"muted": bool}` | mute one namespace |
| PUT | `/api/visibility/namespaces/{ns}/tools` | `{"tool": str, "muted": bool}` | mute one tool |
| GET | `/api/tokens` | — | list the tokens |
| POST | `/api/tokens` | `{"name": str, "scope"?: "mcp"\|"admin", "user_id"?: str}` | create a token, `201` |
| DELETE | `/api/tokens/{id}` | — | revoke a token, `204` |
| POST | `/api/servers/{ns}/approve` | `{"revision": str}` | approve a pending user server |
| GET | `/api/approvals` | — | list the pending servers |
| GET | `/api/users` | — | list the users |
| POST | `/api/users` | `{"id": str, "name"?: str, "groups"?: [str]}` | create a pending user; the answer has `setup_code`, `201` |
| PUT | `/api/users/{id}` | `{"groups"?: [str], "admin"?: bool}` | change the groups or the admin role |
| POST | `/api/users/{id}/setup-code` | — | reset the password; the answer has a new `setup_code` |
| DELETE | `/api/users/{id}` | — | delete a user, `204` |
| GET | `/api/groups` | — | list the groups and their members |
| POST | `/api/groups` | `{"name": str}` | create a group, `201` |
| DELETE | `/api/groups/{name}` | — | delete a group, `204` |
| GET | `/api/rules` | — | list the grant rules |
| POST | `/api/rules` | `{"subject_kind": str, "subject": str, "level": str, "effect": str, "server"?: str, "tool"?: str}` | create a grant rule, `201` |
| DELETE | `/api/rules/{id}` | — | delete a grant rule, `204` |

In the server routes, `{ns}` is a server reference. The reference of an
admin-owned server is `<namespace>`. The reference of a user-owned server is
`<namespace>@<owner>`. The admin creates a user without a password; the user
sets one with the setup code. See [Multiple users](#multiple-users).

A `PUT /api/servers/{ns}` is a full replacement. An omitted field takes the
`ServerSpec` default, so an omitted `enabled` starts a stopped child. Send
`"enabled": false` to keep it stopped.

An error answers with a JSON body `{"error": "<message>"}`. A bad request is
`400`. An unknown namespace or token is `404`. A missing or wrong-scope token
is `401`.

List the servers:

```
curl -H "Authorization: Bearer mcpflow_<admin token>" http://localhost:8000/api/servers
```

## Admin MCP tools

The gateway mounts one built-in MCP server under the namespace `mcpflow`. Its
tools manage the gateway over `/mcp`, so an agent that speaks only MCP adds a
child, reads a log, or unmutes a tool without the REST API. The tools publish
as `mcpflow_<tool>`. An `admin` token is required on `/mcp` to see and call them.
An `mcp` session never lists or calls a `mcpflow_*` tool. A muted root hides the
child tools but never a `mcpflow_*` tool, so an `admin` session can always unmute.

The namespace `mcpflow` and every namespace that starts with `mcpflow_` are reserved.
A child cannot take one, so no child tool name shadows an admin tool.

| Tool | Purpose |
|---|---|
| `mcpflow_list_servers` | list the children |
| `mcpflow_get_server` | one child |
| `mcpflow_add_server` | add a child from a spec and start it |
| `mcpflow_update_server` | replace a child spec; the argument names the child |
| `mcpflow_remove_server` | remove a child |
| `mcpflow_enable_server` | enable a child |
| `mcpflow_disable_server` | disable a child |
| `mcpflow_restart_server` | restart a child |
| `mcpflow_server_log` | the log tail as text, capped at 1000 lines |
| `mcpflow_list_tools` | the tool list with visibility |
| `mcpflow_set_root_muted` | mute or show all child tools |
| `mcpflow_set_namespace_muted` | mute one namespace |
| `mcpflow_set_tool_muted` | mute one child tool |
| `mcpflow_import_from_url` | fetch candidate specs from a URL; adds nothing |
| `mcpflow_write_source` | write inline source files for a child (see Inline source servers) |

`mcpflow_import_from_url` returns candidates only. The agent confirms each one
with `mcpflow_add_server`. No tool mints a token; tokens stay on the REST API and
the tokens page.

Call a tool with an MCP client that sends the `admin` token. For example, with
the FastMCP client:

```python
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

transport = StreamableHttpTransport(
    "http://localhost:8000/mcp",
    headers={"Authorization": "Bearer mcpflow_<admin token>"},
)
async with Client(transport) as c:
    servers = await c.call_tool("mcpflow_list_servers", {})
```

## Secrets

A child can hold a secret in four fields: `env`, `headers`, `url`, and
`source`. The gateway keeps the raw values in `servers.json` (mode `0600`) and
starts each child with the raw values. No read surface shows a raw value.

### What a read shows

The dashboard, the server window, the REST API, and the admin MCP tools show a
masked copy of each child.

| Field | Masked form |
|---|---|
| `env`, `headers` | Each key stays. Each non-empty value becomes `•••`. An empty value stays empty. |
| `url` | The user information and each non-empty query value become `•••`. The scheme, host, path, query keys, and fragment stay. |
| `source` | The user information becomes `***`. |

The gateway masks every value, not only the values of keys that look secret.
Thus `LOG_LEVEL=debug` also reads as `LOG_LEVEL=•••`. Read a non-secret value
in `servers.json`, or write a new value.

The JSON import preview shows the pasted values unchanged, because they are not
stored yet.

### Write a masked record back

A client can read a child, change one field, and send the whole record back.

- Send `•••` for a key that the child already has. The gateway keeps the stored value.
- Send a new value. The gateway replaces the stored value.
- Send the `url` exactly as a read shows it. The gateway keeps the stored `url`.
- Send the `source` exactly as a read shows it. The gateway keeps the stored `source`.

The gateway refuses a write that still holds a mask after this merge. The
answer is `400` on `/api` and a tool error on `/mcp`. The message names the
field and the key, never a value. These writes are refused:

- `•••` under a key that the child does not have, for example after a rename.
- A value that contains the mask, for example `Bearer •••`.
- A `url` with a changed host that keeps a masked query value.
- A new child copied from a read record (`mcpflow_add_server` or `POST /api/servers`).
- A percent-encoded mask in a `url` or a `source`.

Send the real value in each of these cases.

### Logs and errors

- `last_error` and the child log (`/servers/{ns}/log`, `/api/servers/{ns}/log`, `mcpflow_server_log`) mask every secret of the child with `•••`. This includes the decoded forms of a `url` or `source` credential.
- The process log masks the secrets of every child that the process started.
- The access log masks the `code` and `state` query values of the OAuth callback.

### Limits

- `args` is not masked. Put a secret in `env` or `headers`, not in `args`.
- The path of a `url` is not masked. Put a credential in a header when the provider accepts one.
- A secret shorter than 4 characters is not masked in logs and errors.

## Inline source servers

An agent can write a small MCP server as source files and run it, with no git
host and no shell access. The flow is three steps over `/mcp` with an `admin`
token:

1. `mcpflow_write_source(namespace, files)` writes `files` under
   `DATA_DIR/servers/<namespace>/` and returns `path`.
2. `mcpflow_add_server` with kind `python` or `npm`, a `package`, and `source`
   set to the returned `path`. The gateway runs `uvx --from <path> <package>`
   or `npx -y --package=<path> <bin>`.
3. The child's tools appear on `/mcp`.

`files` maps a relative POSIX path to file text. Limits: at most 200 files,
512 KiB per file, 1 MiB total. A key may not be absolute, hold a `.` or `..`
segment, a backslash, or a NUL, and no key may be a directory prefix of
another. A bad key returns a `ToolError` that names the key.

A write replaces the whole tree at once: a file absent from the new `files` is
gone. `restarted` in the result is `true` when the write bounced an existing
`running` or `failed` child onto the new files. It is `false` for a `starting`
child (call `mcpflow_restart_server` once it settles), a `stopped` child
(`enabled` owns the process), and a namespace with no child yet (call
`mcpflow_add_server` next). If a call fails at the restart step, the files are
already written; call `mcpflow_restart_server`.

A child's `source` must point at its own directory. `mcpflow_remove_server`
deletes the directory; `mcpflow_update_server` to a git source and
`mcpflow_disable_server` keep it.

## Development

The project uses `uv` and `pytest`. Run the tests from the repository root.

```sh
uv sync --extra dev
make test
```

The project designs each change with OpenSpec. The development branch `ci`
holds the specs under `openspec/`; the `main` branch holds the code and the
documentation only.

The changelog is [`CHANGELOG.md`](CHANGELOG.md).

The logo lives at `src/mcpflow/static/logo.svg`. The web UI serves the same
file at `/static/logo.svg`.

## License

MIT. See [LICENSE](LICENSE).

MCP Flow runs third-party MCP servers as child processes and proxies remote
ones. Each of those carries its own license; this one covers MCP Flow itself.
