import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


routes = pytest.importorskip("cf_bypasser.server.routes")


@pytest.fixture
def app():
    app = FastAPI()
    routes.setup_routes(app)
    return app


def test_mirror_streaming_response_is_streamed(app):
    async def gen():
        yield b"a"
        yield b"b"

    class FakeMirror:
        async def mirror_request(self, **kwargs):
            return 200, {"content-type": "text/event-stream"}, gen(), True

    original = routes.global_mirror
    routes.global_mirror = FakeMirror()
    try:
        client = TestClient(app)
        resp = client.get("/anything", headers={"x-hostname": "example.com"})
        assert resp.status_code == 200
        assert resp.headers.get("x-streaming") == "true"
        assert resp.text == "ab"
    finally:
        routes.global_mirror = original


def test_mirror_non_streaming_response_is_buffered(app):
    class FakeMirror:
        async def mirror_request(self, **kwargs):
            return 200, {"content-type": "text/plain"}, b"ok", False

    original = routes.global_mirror
    routes.global_mirror = FakeMirror()
    try:
        client = TestClient(app)
        resp = client.get("/anything", headers={"x-hostname": "example.com"})
        assert resp.status_code == 200
        assert resp.headers.get("x-streaming") == "false"
        assert resp.text == "ok"
    finally:
        routes.global_mirror = original

