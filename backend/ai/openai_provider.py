import requests
from .base import BaseAIProvider, AIResult, AIRequestError


class OpenAIProvider(BaseAIProvider):
    """OpenAI Chat Completions API - REST tabanlı."""

    name = "openai"

    def __init__(self, api_key: str, model: str, timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _call(self, system_prompt: str, user_prompt: str, max_tokens: int) -> AIResult:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise AIRequestError(f"OpenAI isteği başarısız: {e}")

        if resp.status_code != 200:
            raise AIRequestError(f"OpenAI API hatası ({resp.status_code}): {resp.text[:500]}")

        data = resp.json()
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            raise AIRequestError(f"OpenAI yanıtı beklenmeyen formatta: {data}")

        return AIResult(text=text, provider=self.name, model=self.model, latency_ms=0, raw=data)
