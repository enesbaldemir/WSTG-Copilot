import requests
from .base import BaseAIProvider, AIResult, AIRequestError


class AnthropicProvider(BaseAIProvider):
    """Anthropic Messages API - REST tabanlı."""

    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _call(self, system_prompt: str, user_prompt: str, max_tokens: int) -> AIResult:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise AIRequestError(f"Anthropic isteği başarısız: {e}")

        if resp.status_code != 200:
            raise AIRequestError(f"Anthropic API hatası ({resp.status_code}): {resp.text[:500]}")

        data = resp.json()
        try:
            text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        except (KeyError, IndexError):
            raise AIRequestError(f"Anthropic yanıtı beklenmeyen formatta: {data}")

        return AIResult(text=text, provider=self.name, model=self.model, latency_ms=0, raw=data)
