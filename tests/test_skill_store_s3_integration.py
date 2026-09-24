"""Real MinIO and gateway acceptance; requires explicit disposable S3 settings."""

import asyncio
import base64
import os
import uuid
from contextlib import closing

import pytest
import test_skill_store_integration as integration
from action_browser import action_post
from test_child_actions import call
from test_child_instructions import _client
from test_skill_store_integration import BODY

real_store = integration.real_store


def test_minio_store_from_actions_page_persists_and_masks_credentials(real_store):
    endpoint = os.environ.get("SKILL_STORE_TEST_S3_ENDPOINT")
    if not endpoint:
        pytest.skip("Set SKILL_STORE_TEST_S3_ENDPOINT and disposable access/secret keys")
    boto3 = pytest.importorskip("boto3")
    access = os.environ["SKILL_STORE_TEST_S3_ACCESS_KEY"]
    secret = os.environ["SKILL_STORE_TEST_S3_SECRET_KEY"]
    bucket = f"skills-integration-{uuid.uuid4().hex}"
    s3 = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=access,
                      aws_secret_access_key=secret, region_name="us-east-1")
    s3.create_bucket(Bucket=bucket)
    server, tokens, _state, _source, _target = real_store
    try:
        with closing(server.login()) as browser:
            response = action_post(browser, "/servers/skills/actions/add_store", data={
                "name": "objectstore", "kind": "s3", "endpoint": endpoint,
                "bucket": bucket, "prefix": "acceptance", "region": "us-east-1",
                "access_key": access, "secret_key": secret,
            })
            assert response.status_code == 200
            assert secret not in response.text and access not in response.text
            response = action_post(browser, "/servers/skills/actions/set_writable", data={"name": "objectstore"})
            assert response.status_code == 200
            response = action_post(browser, "/servers/skills/actions/list_stores", data={})
            assert response.status_code == 200
            assert "objectstore" in response.text
            assert secret not in response.text and access not in response.text
        call(server.base_url, tokens["mcp"], "skills_write_skill", {
            "name": "remote", "files": {"SKILL.md": BODY, "references/data.txt": "S3 content"},
        })
        body = s3.get_object(Bucket=bucket, Key="acceptance/remote/SKILL.md")["Body"].read()
        assert body.decode() == BODY

        async def check_discovery():
            async with _client(server.base_url, tokens["mcp"], mode="legacy") as client:
                assert "objectstore/remote" in client.initialize_result.instructions
                result = await client.read_resource("skill://skills/objectstore/remote/references/data.txt")
                content = result[0]
                actual = content.text.encode() if hasattr(content, "text") else base64.b64decode(content.blob)
                assert actual == b"S3 content"
        asyncio.run(check_discovery())
        with closing(server.login()) as browser:
            response = action_post(browser, "/servers/skills/actions/remove_store", data={"name": "objectstore"})
            assert response.status_code == 200
        assert s3.get_object(Bucket=bucket, Key="acceptance/remote/SKILL.md")["Body"].read().decode() == BODY
        for log in (server.data_dir / "logs").glob("*"):
            text = log.read_text(errors="replace")
            assert secret not in text and access not in text
    finally:
        response = s3.list_objects_v2(Bucket=bucket)
        objects = [{"Key": item["Key"]} for item in response.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
