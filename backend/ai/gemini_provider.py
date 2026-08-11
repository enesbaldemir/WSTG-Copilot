import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .base import BaseAIProvider, AIResult, AIRequestError


class GeminiProvider(BaseAIProvider):
    """
    Google Gemini API (Google AI Studio) - REST tabanlı.
    Ücretsiz katmanı en cömert sağlayıcı olduğu için varsayılan seçimdir.
    https://ai.google.dev/gemini-api/docs
    """

    name = "gemini"

    def __init__(self, api_key: str, model: str, timeout: int = 30):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _build_session(self) -> requests.Session:
        """
        Her istek için taze bir Session + bağlantı havuzu oluşturur ve
        geçici ağ/SSL hatalarında (ör. antivirüs/VPN'in TLS trafiğine
        araya girmesinden kaynaklanan "invalid session id" hataları)
        otomatik olarak yeniden dener.
        """
        session = requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=2,
            backoff_factor=0.75,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
        session.mount("https://", adapter)
        # Bağlantının her seferinde kapatılmasını iste; TLS session
        # resumption'ı bozan proxy/AV yazılımlarında tekrar kullanılan
        # (stale) bir bağlantıya düşmeyi engeller.
        session.headers.update({"Connection": "close"})
        return session

    def _call(self, system_prompt: str, user_prompt: str, max_tokens: int) -> AIResult:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.2,
                # Gemini 3.x ailesi varsayılan olarak "thinking" (iç muhakeme)
                # yapıyor ve bu token'lar da maxOutputTokens bütçesinden
                # düşülüyor. Yapılandırılmış/kısa JSON çıktıları üreten bu
                # görevler için thinking'i düşük tutuyoruz ki asıl cevap
                # token bütçesi bitmeden önce üretilebilsin (aksi halde
                # yanıt "MAX_TOKENS" ile yarım kesilip geçersiz JSON olarak
                # döner).
                "thinkingConfig": {"thinkingLevel": "low"},
            },
        }
        if system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

        last_error = None
        # urllib3'ün Retry mekanizması bağlantı/HTTP seviyesindeki hataları
        # zaten dener; buradaki dış döngü, Retry'nin yakalamadığı düşük
        # seviye SSLError'lar (ör. INVALID_SESSION_ID) için ek bir
        # güvenlik ağıdır.
        for attempt in range(3):
            session = self._build_session()
            try:
                resp = session.post(url, json=payload, timeout=self.timeout)
                break
            except requests.exceptions.SSLError as e:
                last_error = e
                time.sleep(0.5 * (attempt + 1))
                continue
            except requests.RequestException as e:
                raise AIRequestError(f"Gemini isteği başarısız: {e}")
            finally:
                session.close()
        else:
            raise AIRequestError(
                f"Gemini isteği başarısız (SSL): {last_error}. "
                f"Bu hata genellikle antivirüs/VPN yazılımının TLS trafiğine "
                f"araya girmesinden kaynaklanır; bu yazılımlarda 'SSL/HTTPS "
                f"tarama' özelliğini kapatmayı deneyin."
            )

        if resp.status_code != 200:
            raise AIRequestError(f"Gemini API hatası ({resp.status_code}): {resp.text[:500]}")

        data = resp.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            raise AIRequestError(f"Gemini yanıtı beklenmeyen formatta: {data}")

        return AIResult(text=text, provider=self.name, model=self.model, latency_ms=0, raw=data)
