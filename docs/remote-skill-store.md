# Remote skill store

The independent `skill-store` package serves complete skill directories through the Model Context Protocol (MCP).
MCP Flow starts the package as the `skills` child.
The store owns its registry, credentials, files, and writable-store selection.
MCP Flow owns authentication, namespace visibility, and the admin Actions page.

## Install the child

1. Make sure the gateway can reach `https://github.com/bilgili/skill-store`. The entry in `src/mcpflow/catalog/skills.json` installs the store from that repository at a pinned commit.
2. Deploy this gateway version.
3. Create `/data/skill-state` on the persistent gateway volume.
4. Give the gateway user read and write access to this directory.
5. Open the marketplace.
6. Select **Skill Store**.
7. Keep the namespace `skills`.
8. Enter `/data/skill-state` for `SKILLS_STATE_DIR`.
9. Connect the child.
10. Open its **Actions** page.

The catalog grants action capability and preserves `cache_ttl: 0`.
The package source uses a full Git commit identifier.
A catalog entry does not publish the package or make an unavailable Git host reachable.

## Add and select a store

For a directory store, submit `add_store` with these values:

| Field | Value |
| --- | --- |
| name | personal |
| kind | directory |
| path | /data/skill-library |

Create the directory before the action.
Submit `set_writable` with `name=personal`.
Submit `list_stores` to check the selection.
Only the selected writable store accepts `write_skill`.

For an S3-compatible store, select `kind=s3`.
Set the endpoint, bucket, prefix, region, access key, and secret key.
Use an endpoint reachable from the gateway container.
The store keeps credentials in its mode-0600 registry.
Action results mask credentials.

For a Git store, select `kind=git`.
Set its URL and ref.
Git stores accept reads and refreshes.
They cannot become writable stores.

## Import complete directories

Copy each complete skill directory into the directory store.
Preserve every supporting file.
Do not copy only `SKILL.md`.
Reject symbolic links and special files before import.
Run `refresh_store` after the copy.
Compare file contents against the source before removing any local directory.

The original import scope contains shared skills and Claude-only skills.
The inventory can change after the original count of 64 directories.
Count the actual inventory and resolve duplicate directory names before import.
Keep local copies until deployed agent acceptance passes.

## Connect four agents

Use one `mcpflow` entry in each agent configuration.
Preserve unrelated entries.
Use an MCP-scope bearer token for agents.
Keep admin tokens out of agent configuration.
Replace `TOKEN` with the agent token in these examples.

Claude Code stores the user entry in `~/.claude.json`:

```json
{
  "mcpServers": {
    "mcpflow": {
      "type": "http",
      "url": "https://mcp.example/mcp",
      "headers": {"Authorization": "Bearer TOKEN"}
    }
  }
}
```

Codex stores the entry in `~/.codex/config.toml`:

```toml
[mcp_servers.mcpflow]
url = "https://mcp.example/mcp"
bearer_token_env_var = "MCPFLOW_TOKEN"
```

Set `MCPFLOW_TOKEN` in the environment that starts Codex.
An existing `http_headers.Authorization` bearer configuration can remain in place.
Use one authentication method for this entry.

OpenCode stores the entry in `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "mcpflow": {
      "type": "remote",
      "url": "https://mcp.example/mcp",
      "enabled": true,
      "oauth": false,
      "headers": {"Authorization": "Bearer TOKEN"}
    }
  }
}
```

This uses the documented [OpenCode remote-server configuration](https://opencode.ai/docs/mcp-servers/).

Copilot CLI stores the entry in `~/.copilot/mcp-config.json`:

```json
{
  "mcpServers": {
    "mcpflow": {
      "type": "http",
      "url": "https://mcp.example/mcp",
      "headers": {"Authorization": "Bearer TOKEN"},
      "tools": ["*"]
    }
  }
}
```

This uses the documented [Copilot CLI server configuration](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference#mcp-server-configuration).
Copilot can defer initialization instructions until requested.
Explicit use by name remains the required Copilot acceptance check.

## Test the feature

1. Open **Actions** for `skills`.
2. Add the directory store named `personal`.
3. Select it with `set_writable`.
4. Ask an agent to call `skills_write_skill` with the following arguments.

```json
{
  "name": "smoke-test",
  "files": {
    "SKILL.md": "---\nname: smoke-test\ndescription: Check remote skill discovery.\n---\nReply with REMOTE_SKILL_OK.\n",
    "references/check.txt": "Supporting resource content.\n"
  },
  "message": "Verify remote skill persistence",
  "replace": false
}
```

5. Start a fresh agent session.
6. Ask it to use `personal/smoke-test`.
7. Check that `skills_use_skill` returns the exact body.
8. Read `skill://skills/personal/smoke-test/references/check.txt`.
9. Restart the child from the dashboard.
10. Repeat the read.
11. Mute `skills`.
12. Check that its prompts, resources, and catalog block disappear.
13. Unmute `skills`.

Claude Code and Codex must also load the MCP prompt by name.
The gateway prompt name is `skills_personal/smoke-test`.
For clients that reject slashes, set child environment variable `SKILLS_PROMPT_SEPARATOR` to `__`.
Restart the child after this configuration change.
The gateway then lists and resolves `skills_personal__smoke-test`.
The default separator is `/`.
Each skill has exactly one listed prompt in either mode.
Client menus can display a different command prefix.

For automatic selection, use an imported diagnostic skill.
Start a fresh Claude Code session without local skill discovery.
Ask it to debug a failing test.
Verify an actual `skills_use_skill` call before accepting automatic selection.
Protocol tests cannot establish a model's autonomous selection behavior.

## Run the local demonstration

Install both packages in the same Python environment.
Run this command from the gateway checkout:

```sh
python scripts/demo_skill_store.py --root /tmp/mcpflow-skill-demo --port 8791
```

Open `http://127.0.0.1:8791/servers/skills/actions`.
The launcher prints the private credential file path.
Read `admin_password` from that file to log in.
Use its `mcp_token` for an agent connected to `http://127.0.0.1:8791/mcp`.
The launcher never prints credential values.

The demo includes `demo/welcome` and a supporting resource.
Call `skills_use_skill` with `name=demo/welcome`.
Use the Actions page to inspect the directory store or add another store.
Agent writes initially target the separate `demo` directory.

Add existing copied libraries with repeated options:

```sh
python scripts/demo_skill_store.py --root /tmp/mcpflow-skill-demo --port 8791 \
  --library shared=/path/to/copied/shared \
  --library claude=/path/to/copied/claude
```

Use copied directories for experiments that move or replace skills.
Stop the launcher with Control-C.
Run the same command to check persistence.
The launcher refuses a nonempty directory that lacks its demo marker.
It preserves existing skill contents and the current writable-store selection.

## Run the real integration tests

Install both repositories into one test environment.
Clone the store from `https://github.com/bilgili/skill-store`.
Use that checkout for `STORE_REPO`:

```sh
uv venv /tmp/skill-integration-venv
uv pip install --python /tmp/skill-integration-venv/bin/python -e ".[dev]" -e "$STORE_REPO"
/tmp/skill-integration-venv/bin/python -m pytest tests/test_skill_store_integration.py -v
```

The tests start a real gateway and a real store subprocess.
They verify browser actions, fresh discovery, binary resources, restart persistence, migration, scope restrictions, and namespace muting.
Without the separate package, the tests report an explicit skip.
Set `SKILL_STORE_PYTHON` to test an installed child in another environment.

For the actual S3 Actions test, start a disposable MinIO instance.
Set `SKILL_STORE_TEST_S3_ENDPOINT`, `SKILL_STORE_TEST_S3_ACCESS_KEY`, and `SKILL_STORE_TEST_S3_SECRET_KEY`.
Run `tests/test_skill_store_s3_integration.py` in the same test environment.
The test creates a unique bucket and removes that bucket after verification.
It checks actual object contents and credential masking through the rendered Actions page.

## Operational limits

Git refresh runs every 60 seconds or through `refresh_store`.
Removing a store removes its registry entry without deleting backend files.
Migration verifies target contents before deleting a writable source.
Migration from Git preserves the source.
S3 replacement can expose mixed file generations to external readers during publication.
The store's immutable snapshot keeps MCP reads consistent.

Fresh agent sessions receive the updated instruction catalog.
Existing sessions do not receive forwarded list-change notifications.
The catalog has a size limit; use `skills_list_skills` for the complete inventory.
If the gateway is unavailable, each agent's own connection handling controls startup behavior.
Keep local skill directories until outage and prompt behavior pass on all required clients.
