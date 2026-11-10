"""Enforce the project's prohibition on real network calls during tests."""

import socket
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any unexpected outbound connection must fail the test."""

    def blocked(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Real network access is prohibited in tests")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
