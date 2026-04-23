"""Shared test fixtures."""

import pytest

from parry import Guard


@pytest.fixture
def guard():
    return Guard()


@pytest.fixture
def blocking_guard():
    return Guard(mode="block")


@pytest.fixture
def redacting_guard():
    return Guard(mode="redact")
