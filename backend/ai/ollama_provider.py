import requests
from .base import BaseAIProvider, AIResult, AIRequestError


class OllamaProvider(BaseAIProvider):
    """
    Yerel Ollama sunucusu üzerinden çalışan açık kaynak modeller.
    API key gerektirmez; tamamen ücretsizdir ve rate-limit yoktur — bu yüzden
    Faz 5'teki yüksek hacimli deneysel karşılaştırma için ideal bir fallback'tir.
    https://github.com/ollama/ollama
    """

    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_configured(self) -> bool:
        # API key gerekmez; sadece model adının tanımlı olması yeterli.
        return bool(self.model)

    def _call(self, system_prompt: str, user_prompt: str, max_tokens: int) -> AIResult:
        url = f"{self.base_url}/api/generate"
        full_prompt = f"{system_prompt}\n\n{user_prompt}" if system_prompt else user_prompt
        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": 0.2},
        }

        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise AIRequestError(
                f"Ollama'ya bağlanılamadı ({self.base_url}). Yerel sunucunun çalıştığından "
                f"emin olun ('ollama serve'). Detay: {e}"
            )

        if resp.status_code != 200:
            raise AIRequestError(f"Ollama hatası ({resp.status_code}): {resp.text[:500]}")

        data = resp.json()
        text = data.get("response", "")
        return AIResult(text=text, provider=self.name, model=self.model, latency_ms=0, raw=data)
