"""Tests for app/body_limit.py using a tiny app of its own."""

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.body_limit import TOO_LARGE_DETAIL, BodySizeLimitMiddleware


def make_client(max_bytes=1000):
    app = FastAPI()
    calls = {"count": 0}

    @app.post("/echo")
    async def echo(request: Request):
        calls["count"] += 1
        body = await request.body()
        return {"size": len(body)}

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_bytes)
    return app, calls


def test_small_and_exactly_at_the_limit_bodies_pass():
    app, calls = make_client(max_bytes=1000)
    with TestClient(app) as client:  # also proves startup/shutdown are untouched
        assert client.post("/echo", content=b"x" * 500).json() == {"size": 500}
        assert client.post("/echo", content=b"x" * 1000).json() == {"size": 1000}
        assert client.get("/ping").json() == {"ok": True}
    assert calls["count"] == 2


def test_a_declared_length_over_the_limit_is_refused_before_the_app_runs():
    app, calls = make_client(max_bytes=1000)
    client = TestClient(app)

    response = client.post("/echo", content=b"x" * 1001)

    assert response.status_code == 413
    assert response.json() == {"detail": TOO_LARGE_DETAIL}
    assert calls["count"] == 0


def test_a_body_with_no_declared_length_is_still_stopped():
    app, calls = make_client(max_bytes=1000)
    client = TestClient(app)

    def chunks():
        yield b"x" * 600
        yield b"x" * 600

    response = client.post("/echo", content=chunks())

    assert response.status_code == 413
    assert response.json() == {"detail": TOO_LARGE_DETAIL}