"""Tests for ApiRegistry."""

from __future__ import annotations

from auth0_api_python import ApiRegistry, DownstreamApi


class TestApiRegistry:
    def test_get_returns_registered_entry(self) -> None:
        api = DownstreamApi(audience="https://api.example.com")
        registry = ApiRegistry([api])
        assert registry.get("https://api.example.com") is api

    def test_get_returns_none_for_unregistered_audience(self) -> None:
        api = DownstreamApi(audience="https://api.example.com")
        registry = ApiRegistry([api])
        assert registry.get("https://other.example.com") is None

    def test_get_returns_none_from_empty_registry(self) -> None:
        registry = ApiRegistry([])
        assert registry.get("https://api.example.com") is None

    def test_multiple_entries_are_keyed_by_audience(self) -> None:
        api_a = DownstreamApi(audience="https://a.example.com")
        api_b = DownstreamApi(audience="https://b.example.com")
        registry = ApiRegistry([api_a, api_b])
        assert registry.get("https://a.example.com") is api_a
        assert registry.get("https://b.example.com") is api_b
