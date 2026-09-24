"""redact-process-log: the mcpflow process log holds no child secret.

Scenarios from `openspec/changes/redact-process-log/specs/mcp-gateway/spec.md`
(Process log hides child secrets). Each test uses its own secret values: the
remembered set is process-wide and only grows.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import urlsplit

import httpx
import pytest
import pytest_asyncio
from conftest import fake_child_spec, make_settings

from mcpflow.gateway import build_app
from mcpflow.oauth import CredStore, PendingFlows
from mcpflow.registry import (
    SECRET_MASK,
    Registry,
    RegistryError,
    ServerSpec,
    redact_url,
    source_secrets,
    url_secrets,
)
from mcpflow.supervisor import (
    REDACTION_FAILED,
    Supervisor,
    install_log_redaction,
    remember_log_secrets,
)

# A port nothing listens on, so a remote child fails its probe at once.
DEAD = "http://127.0.0.1:9"


@pytest.fixture(autouse=True)
def _redactor():
    install_log_redaction()


@pytest_asyncio.fixture
async def sup(tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    s = Supervisor(reg, make_settings(tmp_path), CredStore(tmp_path), PendingFlows())
    yield s
    await s.shutdown()


async def _started(sup: Supervisor, spec: ServerSpec):
    child = await sup.add(spec)
    await child.task
    return child


def _remote(ns: str, url: str, **extra) -> ServerSpec:
    return ServerSpec(namespace=ns, kind="remote", url=url, transport="sse", **extra)


def _only(caplog, name: str) -> logging.LogRecord:
    records = [r for r in caplog.records if r.name == name]
    assert len(records) == 1
    return records[0]


@pytest.mark.asyncio
async def test_sse_writer_exception_masks_the_url_credential(sup, caplog):
    url = f"{DEAD}/sse?api_key=k-999999-secret"
    await _started(sup, _remote("quiver", url))
    caplog.set_level(logging.ERROR, logger="mcp.client.sse")
    try:
        raise httpx.ConnectError(f"All connection attempts failed: {url}")
    except httpx.ConnectError:
        logging.getLogger("mcp.client.sse").exception("Error in post_writer to %s", url)
    record = _only(caplog, "mcp.client.sse")
    assert "k-999999-secret" not in caplog.text
    assert SECRET_MASK in record.getMessage()
    assert SECRET_MASK in record.exc_text
    assert "k-999999-secret" not in record.exc_text
    assert record.exc_info is None


@pytest.mark.asyncio
async def test_httpx_request_line_masks_the_encoded_form(sup, caplog):
    url = f"{DEAD}/sse?api_key=k 99ä999-secret"
    await _started(sup, _remote("quiver2", url))
    caplog.set_level(logging.INFO, logger="httpx")
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    with httpx.Client(transport=transport) as client:
        client.get(url)
    record = _only(caplog, "httpx")
    assert "k%2099%C3%A4999-secret" not in caplog.text
    assert "k 99ä999-secret" not in caplog.text
    assert SECRET_MASK in record.getMessage()


@pytest.mark.asyncio
async def test_removed_child_secret_stays_masked(sup, caplog):
    spec = fake_child_spec("gitlab", "good", env={"TOKEN": "glpat-abc-secret-1"})
    await _started(sup, spec)
    await sup.remove("gitlab")
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcp.client.stdio").error("late: glpat-abc-secret-1")
    assert "glpat-abc-secret-1" not in caplog.text


@pytest.mark.asyncio
async def test_replaced_generation_secret_stays_masked(sup, caplog):
    old = {"Authorization": "Bearer tok-old-secret-1"}
    await _started(sup, _remote("hs", f"{DEAD}/mcp", headers=old))
    new = {"Authorization": "Bearer tok-new-secret-2"}
    child = await sup.update(_remote("hs", f"{DEAD}/mcp", headers=new))
    await child.task
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcp.client.sse").error("old token tok-old-secret-1 rejected")
    assert "tok-old-secret-1" not in caplog.text


@pytest.mark.asyncio
async def test_record_after_the_lifespan_ends_is_masked(tmp_path, caplog):
    app = build_app(make_settings(tmp_path))
    async with app.router.lifespan_context(app):
        await _started(
            app.state.supervisor, _remote("late", f"{DEAD}/sse?token=lifespan-secret-9")
        )
    caplog.set_level(logging.ERROR)
    logging.getLogger("asyncio").error("Task exception: lifespan-secret-9")
    assert "lifespan-secret-9" not in caplog.text


def test_record_without_a_secret_keeps_its_structure(caplog):
    remember_log_secrets(["structure-secret-3"])
    caplog.set_level(logging.ERROR)
    try:
        raise ValueError("boom")
    except ValueError:
        logging.getLogger("mcpflow.test").exception("plain %s %d", "text", 7)
    record = _only(caplog, "mcpflow.test")
    assert record.msg == "plain %s %d"
    assert record.args == ("text", 7)
    assert record.exc_info is not None


def test_secret_in_args_keeps_the_template(caplog):
    remember_log_secrets(["args-secret-4"])
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcpflow.test").error("token %s at %d", "args-secret-4", 7)
    record = _only(caplog, "mcpflow.test")
    assert record.msg == "token %s at %d"
    assert record.args == (SECRET_MASK, 7)


def test_secret_in_a_non_str_arg_flattens(caplog):
    remember_log_secrets(["obj-secret-5"])
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcpflow.test").error("failed: %s", ValueError("obj-secret-5"))
    record = _only(caplog, "mcpflow.test")
    assert record.args is None
    assert record.msg == f"failed: {SECRET_MASK}"


def test_secret_in_a_mapping_arg_flattens(caplog):
    remember_log_secrets(["map-secret-6"])
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcpflow.test").error("%(k)s", {"k": "map-secret-6"})
    record = _only(caplog, "mcpflow.test")
    assert record.args is None
    assert record.msg == SECRET_MASK


def test_secret_in_stack_info_is_masked(caplog):
    # The stack text names this frame; treat that name as the secret.
    name = "test_secret_in_stack_info_is_masked"
    remember_log_secrets([name])
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcpflow.test").error("here", stack_info=True)
    record = _only(caplog, "mcpflow.test")
    assert name not in record.stack_info
    assert SECRET_MASK in record.stack_info


def test_scrub_failure_fails_closed(caplog):
    remember_log_secrets(["fail-secret-8"])
    caplog.set_level(logging.ERROR)
    try:
        raise ValueError("fail-secret-8")
    except ValueError:
        logging.getLogger("mcpflow.test").exception("%s %s", "only-one")  # noqa: PLE1206 - bad record on purpose
    record = _only(caplog, "mcpflow.test")
    assert record.getMessage() == REDACTION_FAILED
    assert record.exc_info is None
    assert record.exc_text is None
    assert "fail-secret-8" not in caplog.text


def test_extra_fields_still_merge():
    remember_log_secrets(["extra-secret-9"])
    logger = logging.getLogger("mcpflow.test")
    record = logger.makeRecord(
        "mcpflow.test", logging.ERROR, __file__, 1, "x extra-secret-9", None, None,
        extra={"client": "c"},
    )
    assert record.client == "c"
    assert "extra-secret-9" not in record.getMessage()


def test_one_redactor_per_process(tmp_path):
    build_app(make_settings(tmp_path / "a"))
    first = logging.Logger.makeRecord
    build_app(make_settings(tmp_path / "b"))
    install_log_redaction()
    assert logging.Logger.makeRecord is first


def test_extra_fields_are_masked(caplog):
    # A child's log notification `extra` reaches the process log through
    # fastmcp's proxy handler; the scrub must see it after the merge.
    remember_log_secrets(["extra-field-secret-10"])
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcpflow.test").error(
        "note",
        extra={"child": "k=extra-field-secret-10", "nested": {"t": "extra-field-secret-10"}, "n": 3},
    )
    record = _only(caplog, "mcpflow.test")
    assert record.child == f"k={SECRET_MASK}"
    assert "extra-field-secret-10" not in record.nested
    assert record.n == 3


def test_secret_split_between_template_and_args_flattens(caplog):
    remember_log_secrets(["abcdef-span-secret"])
    caplog.set_level(logging.ERROR)
    logging.getLogger("mcpflow.test").error("tok=abc%s", "def-span-secret")
    record = _only(caplog, "mcpflow.test")
    assert record.args is None
    assert record.msg == f"tok={SECRET_MASK}"


# Two shapes `urlsplit` rejects (its error echoes the netloc, not the whole
# URL; codex round 2): a bad character in the password, which `httpx` still
# accepts and re-encodes, and one in the host, which `httpx` rejects too.
BAD_URL_SHAPES = [
    "http://user:{s}\uff1a@host.test/x",
    "http://user:{s}@ho\uff1ast.test/x",
]


@pytest.mark.parametrize("shape", BAD_URL_SHAPES)
def test_unparseable_url_parse_error_is_masked(shape, caplog):
    secret = f"parse-err-secret-{BAD_URL_SHAPES.index(shape)}"
    url = shape.format(s=secret)
    remember_log_secrets(url_secrets(url))
    caplog.set_level(logging.ERROR)
    try:
        urlsplit(url)
    except ValueError as exc:
        logging.getLogger("mcpflow.test").error("bad url: %s", exc)
    assert secret not in caplog.text
    assert SECRET_MASK in caplog.text


# Every shape the extractors cannot cut is refused at the write boundary
# (codex round 3): NFKC in the password or the host, scheme-relative, and a
# control character that `urlsplit` silently deletes.
REFUSED_URL_SHAPES = [
    *BAD_URL_SHAPES,
    "//user:{s}@ho\uff1ast.test/x",
    "http://user:line\nbreak-{s}@host.test/x",
]


@pytest.mark.parametrize("shape", REFUSED_URL_SHAPES)
@pytest.mark.asyncio
async def test_unparseable_url_is_refused_without_echo(shape, sup, caplog):
    secret = f"refused-secret-{REFUSED_URL_SHAPES.index(shape)}"
    caplog.set_level(logging.DEBUG)
    with pytest.raises(RegistryError) as err:
        await sup.add(_remote("bad", shape.format(s=secret)))
    assert str(err.value) == "url: not a valid http(s) URL"
    assert secret not in caplog.text
    assert [s.namespace for s in sup.registry.list()] == []


@pytest.mark.parametrize(
    "url",
    [
        "ftp://u:x-1@host.test/x",
        "//u:x-1@host.test/x",
        "http://u:x-1@host.test:abc/x",
        "https://u:x-1@/mcp",
    ],
)
def test_url_a_remote_transport_cannot_use_is_refused(url, tmp_path):
    # Not a leak (these parse, and httpx names only the port), but a remote
    # child that can never start is refused at the same boundary.
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    with pytest.raises(RegistryError, match="url: not a valid http"):
        reg.add(_remote("r", url))


@pytest.mark.parametrize(
    "source",
    [
        "git+https://oauth2:src-secret-1\uff1a@ho\uff1ast.test/o/r",
        "git+https://oauth2:src\nsecret-2@host.test/o/r",
    ],
)
def test_unparseable_source_is_refused_without_echo(source, tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    spec = ServerSpec(namespace="src", kind="python", package="p", source=source)
    with pytest.raises(RegistryError) as err:
        reg.add(spec)
    assert str(err.value) == "source: not a valid URL"


def test_unused_mapping_arg_secret_never_reaches_handle_error(capsys):
    # A formatter fault makes `handleError` print the record's args; an arg
    # the message never rendered must not hold a secret by then.
    remember_log_secrets(["unused-arg-secret-11"])
    logger = logging.getLogger("mcpflow.test.unused")
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s count=%(count)d"))
    logger.addHandler(handler)
    try:
        logger.error(
            "request failed: %(reason)s",
            {"reason": "timeout", "token": "unused-arg-secret-11"},
            extra={"count": "not-a-number"},
        )
    finally:
        logger.removeHandler(handler)
    err = capsys.readouterr().err
    assert "Arguments" in err
    assert "unused-arg-secret-11" not in err


def test_unparseable_url_registers_the_bare_password():
    # A diagnostic can echo the password alone; `source` goes through the
    # same fallback, since `_secrets_of` extracts it with `source_secrets`.
    url = BAD_URL_SHAPES[1].format(s="bare-pw-secret-1")
    assert "bare-pw-secret-1" in url_secrets(url)
    assert "bare-pw-secret-1" in source_secrets(url)


def test_url_secrets_hold_the_httpx_userinfo_form():
    got = url_secrets("https://user:p\u00e4ss word-9@host.test/mcp")
    assert "p%C3%A4ss%20word-9" in got


@pytest.mark.parametrize("shape", REFUSED_URL_SHAPES)
def test_redact_url_never_raises_on_an_unparseable_url(shape):
    # The marketplace refusal page re-renders a refused catalog URL through
    # `redact_url` (codex round 4); a raise there logs the netloc.
    secret = f"redact-view-secret-{REFUSED_URL_SHAPES.index(shape)}"
    shown = redact_url(shape.format(s=secret))
    assert secret not in shown


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1]:8080/mcp?api_key=v6-secret-1",
        "https://b\u00fccher.example/mcp",
        "https://us%40er:p%3Ass@host.test/mcp",
    ],
)
def test_legitimate_url_shapes_are_accepted(url, tmp_path):
    reg = Registry(tmp_path / "servers.json")
    reg.load()
    reg.add(_remote("ok", url))
    assert reg.get("ok").url == url


def test_marketplace_refusal_page_renders_a_bad_catalog_url(server_factory):
    # Codex round 4: the refused connect re-renders the entry preview through
    # `redact_url`; a raise there was a 500 whose traceback held the netloc.
    url = "http://user:catalog-secret-777：@ho：st.test/mcp"

    def seed(data_dir):
        (data_dir / "catalog").mkdir()
        (data_dir / "catalog" / "acme.json").write_text(json.dumps({
            "id": "acme", "name": "Acme", "vendor": "Acme", "category": "dev",
            "color": "#000000", "description": "Bad URL.", "auth": "none",
            "tools": ["acme_x"],
            "spec": {"kind": "remote", "url": url, "transport": "http"},
        }))

    client = server_factory(seed).login()
    detail = client.get("/marketplace/acme")
    connect = client.post("/marketplace/acme/connect", data={"namespace": "acme"})
    client.close()
    assert detail.status_code == 200
    assert "catalog-secret-777" not in detail.text
    assert 400 <= connect.status_code < 500
    assert "url: not a valid http(s) URL" in connect.text
    assert "catalog-secret-777" not in connect.text
