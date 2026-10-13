# Changelog

This file records the user-visible changes of MCP Flow, a gateway for Model Context Protocol (MCP) servers, from 2026-10-02 to 2026-10-13. The package `mcpflow` stays at version 0.1.0 and has no release tags, so each section shows a ship date.

## 2026-10-13

### Changed

- The README and `docs/multi-user-access.md` now describe the `/security` page, the setup-code sign-in, the write-time check of the acting user, the cross-site check, the lazy tool tree, and the multi-user routes of `/api`.

### Dependencies

- The package requires `fastmcp>=4.1.0,<5`, `jinja2>=3.1.6`, `python-multipart>=0.0.32`, and `httpx>=0.28.1`. The earlier floors were `fastmcp>=4.0.11`, `jinja2>=3.1`, `python-multipart>=0.0.20`, and `httpx>=0.27`.
- The full test suite passes on `fastmcp` 4.1.0 and `mcp` 2.3.0. The Docker image installs dependencies without pins, so a new build takes the newest release inside these bounds.

## 2026-10-09

### Changed

- `GET /` renders the dashboard page at once and loads the tool tree from `/tools/tree` after the page paints. A slow server no longer holds the page or the sign-in redirect.
- The tool tree, `GET /api/tools`, and the `mcpflow_list_tools` tool answer from a stored tool list of each running server. They wait for no server.
- A stored list that is older than 10 seconds starts one background read of that server. The tree polls `/tools/tree?poll=1` every 3 seconds while a read runs, and a poll answer starts no read.
- A mute or unmute control answers at once. The list on screen can be up to one read cycle old, and the next `GET /api/tools` call shows the fresh list.
- The first background read after a list goes stale marks a dead running server as failed. Before, every render of the tree did this.

### Fixed

- A dashboard request without a session no longer puts the login page inside the dashboard. The tree load, the tree poll, and the visibility controls now get `401` with the header `HX-Redirect`. The browser opens the full login page, and the user returns to the page that sent the request.
- `POST /login` refuses a `next` value that starts with `/\` and sends the user to `/`.

## 2026-10-08

### Changed

- `POST /api/tokens` and `POST /tokens` answer `400` with the text `user_id: unknown user <id>` for an unknown user. They answered `404` before.
- `POST /api/users` and `PUT /api/users/{id}` check the user in the path and the actor before the group names in the body. A request with two faults can get a different answer than before.

### Fixed

- A call by hashed tool name works on `fastmcp` 4.0.11 and newer. On those releases, the gateway answered an unknown-tool error to a hashed call that the caller may make.
- `POST /users/{id}/groups` and `POST /groups/{name}/members` answer `400` when a name in the request body equals the name in the path. The text names the unknown group or user. These routes answered `404` before.
- A refused `POST /api/users` or `POST /users` no longer rewrites `user_tokens.json` or `rules.json`.
- A header-sink server holds an Open Authorization (OAuth) access token in its `Authorization` header. The gateway renews that token for a public Proof Key for Code Exchange (PKCE) client. Each refresh round starts from `refresh.json` under `creds/<ref>/` in `DATA_DIR`. A failed header write no longer makes the refresh task send a revoked refresh token or ask for a new authorization.
- A `refresh.json` that the gateway cannot read, or that holds an expiry time that is not a finite number, shows as a rejection. The gateway still starts.
- A temporary refresh error shows `refresh failing (<cause>); retrying` after the access token expires. The text clears when the refresh works again.

### Security

- A cross-site `POST` to `/login` or `/login/setup` answers `403` with `cross-origin request rejected`. The gateway sets no cookie and uses no setup code. This closes login Cross-Site Request Forgery (CSRF), where a hostile page signs the browser of a user in to another account.
- The cross-site check covers every `POST` except the bearer paths `/mcp` and `/api/*`, which take no cookie. A cross-origin `POST` to `/health`, `/static/*`, or `/.well-known/*` now answers `403`.
- The bearer paths match on a path segment. `/mcp` covers `/mcp` and `/mcp/x`, and does not cover `/mcpfoo`.

### Dependencies

- The package requires `fastmcp>=4.0.11,<5`. The cap `<4.0.11` of 2026-10-05 is gone, and the earlier floor was `fastmcp>=4.0.2`.

## 2026-10-07

### Added

- The Users section of `/security` has a `+ Create user` button that opens a dialog. A refused create opens the dialog again with the reason.
- Each user row has a menu with `Edit user`, `Reset password`, and `Delete`. `Delete` asks for confirmation in a dialog.
- `Edit user` opens a dialog with a filter box and a checklist of groups. The dialog sends only the groups that the admin changes, so an open dialog cannot undo a change of another admin.
- The Groups section has a `+ Create group` button and a row menu with `Edit members` and `Delete`. `Edit members` posts to the new route `POST /groups/{name}/members` and applies the changes in one write.

### Changed

- The admin role is membership of the reserved group `admins`. The group always exists, no operation deletes it, and the user `admin` always stays a member.
- The Users section has no Admin column, no `Make admin` or `Revoke` button, and no Admin checkbox. The route `POST /users/{id}/admin` is gone. To make an admin, add the user to `admins`.
- `users.json` moves to version 2. The first start of the new build migrates a version 1 file in one write and keeps every role. An earlier build refuses a version 2 file.
- `/api` keeps the `admin` field of a user and maps it to membership of `admins`. The `groups` field lists `admins` for an admin user.
- The Rules section refuses a grant rule on the group `admins`, because members of `admins` skip the grant rules.
- Group tags are rounded chips with the × inside. The `admins` chip shows a shield. The chip of the user `admin` shows a lock and has no ×.

### Fixed

- A web route that adds a server answers `403` when the actor lost the admin role during the request. The route answered `500` before.
- A disk permission fault (`EACCES`) answers `500`. It answered `403` and showed the operating system text.
- The Enter key in the filter box of a user dialog or a members dialog submits nothing. Before, Enter saved or created a user.
- A user who may not run the action of a server gets `403`, not a transport error. The gateway checks the user before it lists the tools of the server.
- A user id such as `group-eng` no longer shares a dialog id with the group `eng`. Before, `Delete` of the group opened the dialog of the user.
- `Edit members` no longer fails when the admin deleted a listed user after the dialog opened.

### Security

- A password reset revokes every token of the user before it makes the user pending. Before, a thief kept the token of a reset admin and kept access to `/api`.
- Every write that needs the admin role reads the user again at write time. The gateway refuses a request of an admin who lost the role, or of a deleted user, with `403`.
- The same check covers each write to a server: update, remove, approve, enable, disable, restart, the mute controls, source write, action run, and OAuth completion.
- A request of a deleted user cannot land after an admin creates the same user id again.

## 2026-10-06

### Added

- Each membership tag has a red × button. The button removes the user from the group through the new route `POST /groups/{name}/members/{user_id}/remove`.

### Changed

- One admin page, `/security`, holds the Users, Groups, and Rules sections. The header shows one `Security` link in place of `Users`, `Groups`, and `Rules`.
- `GET /users`, `GET /groups`, and `GET /rules` redirect with `303` to `/security#users`, `/security#groups`, and `/security#rules`.
- The write routes keep their paths. A success returns to the anchor of its section. A refusal renders `/security` with `400` and shows the error in the section that failed.
- A membership list of more than three tags shows the first three and a `+N more` control. The control opens the rest in place and needs no JavaScript.

## 2026-10-05

### Added

- The public page `/login/setup` takes the user id, the setup code, and a new password twice. A valid code sets the password, ends the pending state, and signs the user in.
- Every signed-in user has the page `/settings` and a `Settings` link in the header. The page changes the password after it checks the current password.
- `POST /api/users/{id}/setup-code` resets the password of a user and returns a new `setup_code` once.
- `/users` and `GET /api/users` show whether a user is pending.

### Changed

- The create form of `/users` has no password field. The new user is pending, and the gateway shows a single-use setup code once. The code ends after 7 days.
- The per-row `Set password` form becomes `Reset password`. A reset makes the user pending again and shows a new setup code once.
- `POST /api/users` takes no `password` and answers `201` with `setup_code` once. `PUT /api/users/{id}` answers `400` for a request with `password`.
- The user `admin` is unchanged. `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH` owns its password, and `/settings` says so.

### Security

- The admin no longer chooses or knows the password of a user. A password has at least 8 characters.
- A password change on `/settings` keeps the current browser signed in and ends every other session of the user.
- The setup page gives one error for an unknown user, a wrong code, an expired code, and an active user. Every refusal waits 1 second.

### Dependencies

- The package requires `fastmcp>=4.0.2,<4.0.11`. Release 4.0.11 changed the lookup of a hashed tool name. The cap holds the package on the tested range until the gateway supports it.

## 2026-10-04

### Added

- The new settings `MAX_USER_SERVERS` (default `20`) and `MAX_USER_TOKENS` (default `10`) limit what one non-admin user owns. A value of `0` allows none, and a value that is not an integer of `0` or more stops the start.
- A refused add or mint names the setting and its value. The admin has no server limit and mints tokens past the token limit.

### Fixed

- A user who adds many pending servers no longer slows `/mcp` for every user. The gateway computes the approval revision of a server record once and keeps it.
- Two servers that publish the same prompt name, resource address, or resource template address no longer reach the wrong server. The router drops the name from the list, answers a get with "not found", and logs one warning for each name.
- A server that fails no longer opens a wrong target. While a server fails, the router refuses each name that the failed server may own, in the list and in the call. The router hides those names of other servers too until the server recovers.

## 2026-10-02

### Added

- MCP Flow serves more than one user from one gateway. Each user has an id, a name, and groups. The admin creates users and groups on the dashboard or on `/api/users` and `/api/groups`.
- Sign-in takes a `user` and a `password`. An empty `user` means `admin`, and `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH` stays the password of that user.
- Grant rules let or stop one user or one group from using a server or a tool. The levels are `global`, `server`, and `tool`, and one `deny` wins. The admin manages rules on `/rules` and on `/api/rules`.
- Each token belongs to one user. A non-admin user mints and revokes only their own `mcp` tokens on `/tokens`. The admin mints a token of either scope for any user.
- The gateway shows each user only the servers and tools that the grant rules allow, on `/mcp`, in the handshake instructions, and on the dashboard. Every request applies the current rules.
- A non-admin user adds a server of the kind `python`, `npm`, or `remote`. The server stays pending and starts no process and no connection until the admin approves it.
- The admin reviews pending servers on `/approvals` and on `GET /api/approvals`. The admin approves with `POST /api/servers/{ref}/approve` and the revision that the admin read. A changed server answers `409`.
- A server reference is `<namespace>` for an admin-owned server and `<namespace>@<owner>` for a user-owned server. Every `/api/servers/{ref}` route takes this reference.
- Two users can own the same namespace. Credentials, source files, and logs are kept for each server reference.
- The gateway refuses a user-owned server that does not name immutable code. A `npm` or `python` package needs an exact version. A `source` needs a full 40-character commit hash.
- The gateway also refuses the kind `custom` for a user-owned server. It refuses an `env` key that changes which code the server loads.

### Changed

- An edit of the command, the package, the URL, the headers, the `env`, or the source of a server sets the server back to pending. This rule covers the admin too.
- A non-admin user never sees a `mcpflow_*` tool. The admin MCP view holds admin-owned servers only, and the admin manages user-owned servers on the dashboard and on `/api`.
- The global mute hides a tool from every caller, the admin included. The mute covers user-owned servers.
- A non-admin user reaches only the dashboard, the server pages of the user, the add-server form, and the token pages. Every other dashboard route answers `403`.
- A non-admin user who opens a server that the user does not own gets `404`.
- The gateway refuses a user write that makes a tool name ambiguous with an admin-owned namespace, for example `github_create` next to `github`.
- New files appear under `DATA_DIR`: `users.json`, `user_servers.json`, `user_tokens.json`, and `rules.json`. `servers.json` and `tokens.json` keep their format.

### Upgrade notes

- The upgrade needs no manual step. An existing server, an old `mcp` token, and an old `admin` token work as before.
- The session cookie changes format, so the upgrade signs every browser session out once. Sign in again with the user `admin`, or leave the user empty, and use the same password.
- A downgrade fails closed. The earlier build reads `servers.json` and `tokens.json` only. It starts no user server, accepts no token of another user, and sees no second server under one namespace.

## Earlier history

Changes before 2026-10-02 are in the git history and in `README.md`.
