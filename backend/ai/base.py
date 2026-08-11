"""
AI Provider soyutlama katmanı (Faz 0).

Bu modül, farklı LLM sağlayıcılarının (Gemini, OpenAI, Anthropic, Ollama)
tek bir ortak arayüz üzerinden çağrılabilmesini sağlar. Böylece:

  1. Sağlayıcı .env üzerinden (AI_PROVIDER) değiştirilebilir, kod
     değişikliği gerekmez.
  2. Faz 5'teki deneysel karşılaştırma (örn. "Gemini vs yerel model")
     için aynı arayüz üzerinden birden fazla sağlayıcı test edilebilir.
  3. Üst katmanlar (finding analizi, sonraki test önerisi, rapor
     üretimi) sağlayıcı detaylarından tamamen habersiz kalır.
"""

import time
from dataclasses import dataclass
from typing import Optional


class AIConfigError(Exception):
    """Sağlayıcı için gerekli API key / config eksik olduğunda fırlatılır."""
    pass


class AIRequestError(Exception):
    """Sağlayıcıya yapılan istek başarısız olduğunda fırlatılır (ağ, 4xx/5xx, timeout)."""
    def __init__(self, message, latency_ms=None):
        super().__init__(message)
        self.latency_ms = latency_ms


@dataclass
class AIResult:
    text: str                 # modelin ürettiği ham metin
    provider: str              # 'gemini' | 'openai' | 'anthropic' | 'ollama'
    model: str                 # kullanılan model adı
    latency_ms: int             # istek süresi (ms) — Faz 5 metrikleri için
    raw: Optional[dict] = None  # sağlayıcının ham JSON yanıtı (debug amaçlı)


class BaseAIProvider:
    """Tüm sağlayıcıların uyması gereken ortak arayüz."""

    name = "base"

    def is_configured(self) -> bool:
        raise NotImplementedError

    def _call(self, system_prompt: str, user_prompt: str, max_tokens: int) -> AIResult:
        raise NotImplementedError

    def chat(self, system_prompt: str, user_prompt: str, max_tokens: int = 1024) -> AIResult:
        """
        Ortak giriş noktası: config kontrolü + süre ölçümü burada yapılır,
        sağlayıcıya özgü HTTP çağrısı `_call` içinde gerçekleşir.
        """
        if not self.is_configured():
            raise AIConfigError(
                f"'{self.name}' sağlayıcısı için gerekli API key/config bulunamadı. "
                f".env dosyanızı kontrol edin."
            )
        start = time.monotonic()
        try:
            result = self._call(system_prompt, user_prompt, max_tokens)
        except AIRequestError as e:
            e.latency_ms = int((time.monotonic() - start) * 1000)
            raise
        except Exception as e:  # sağlayıcıya özgü SDK/HTTP hatalarını tekilleştir
            raise AIRequestError(str(e), latency_ms=int((time.monotonic() - start) * 1000))
        result.latency_ms = int((time.monotonic() - start) * 1000)
        return result
