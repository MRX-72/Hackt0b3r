"""Pluggable local LLM clients: Ollama and any OpenAI-compatible server (llama.cpp llama-server)."""

import json
from http import HTTPStatus
from typing import Any, Protocol

from sentinel.config.settings import LlmSettings
from sentinel.net.http import Request, Transport, TransportError, json_request, urllib_transport


class LlmError(Exception):
    pass


class LlmClient(Protocol):
    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str: ...
    def models(self) -> list[str]: ...


class _Base:
    def __init__(self, s: LlmSettings, api_key: str | None, transport: Transport) -> None:
        self._s = s
        self._base = s.base_url.rstrip("/").removesuffix("/v1")
        self._key = api_key
        self._transport = transport

    def _call(self, request: Request) -> Any:
        try:
            response = self._transport(request)
        except TransportError as exc:
            raise LlmError(f"cannot reach the LLM server: {exc}") from exc
        if response.status != HTTPStatus.OK:
            raise LlmError(f"LLM server returned HTTP {response.status}")
        try:
            return json.loads(response.body)
        except ValueError as exc:
            raise LlmError("LLM server returned non-JSON") from exc

    def _request(self, method: str, url: str, payload: Any) -> Request:
        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        return json_request(method, url, payload, headers, self._s.timeout_seconds)


class OllamaClient(_Base):
    """Native /api/chat; `format` takes a JSON schema (structured outputs)."""

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload = {
            "model": self._s.model, "stream": False, "format": schema,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": self._s.temperature},
        }  # fmt: skip
        body = self._call(self._request("POST", f"{self._base}/api/chat", payload))
        try:
            return str(body["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise LlmError("unexpected Ollama response shape") from exc

    def models(self) -> list[str]:
        body = self._call(self._request("GET", f"{self._base}/api/tags", None))
        return [str(m["name"]) for m in body.get("models", [])]


class OpenAICompatClient(_Base):
    """/v1/chat/completions with response_format json_schema (llama.cpp llama-server, vLLM, ...)."""

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload = {
            "model": self._s.model, "temperature": self._s.temperature,
            "response_format": {"type": "json_schema", "schema": schema},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }  # fmt: skip
        url = f"{self._base}/v1/chat/completions"
        body = self._call(self._request("POST", url, payload))
        try:
            return str(body["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError("unexpected OpenAI-compatible response shape") from exc

    def models(self) -> list[str]:
        url = f"{self._base}/v1/models"
        body = self._call(self._request("GET", url, None))
        return [str(m["id"]) for m in body.get("data", [])]


def build_client(
    s: LlmSettings, api_key: str | None = None, transport: Transport = urllib_transport
) -> LlmClient | None:  # fmt: skip
    """None when the LLM is disabled, so callers use the template path."""
    if not s.enabled:
        return None
    cls = OllamaClient if s.runtime == "ollama" else OpenAICompatClient
    return cls(s, api_key, transport)
