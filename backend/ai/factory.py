from .gemini_provider import GeminiProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama_provider import OllamaProvider


def get_ai_provider(app_config):
    """
    app_config.AI_PROVIDER değerine göre uygun sağlayıcıyı döner.
    Üst katmanlar (routes, ai analiz fonksiyonları) hep bu fonksiyonu
    çağırır; sağlayıcı değişince başka hiçbir yeri değiştirmeye gerek yoktur.

    app_config: bir sınıf (DevelopmentConfig gibi, nokta erişimi) ya da
    Flask'ın app.config nesnesi (dict-benzeri, ['KEY'] erişimi) olabilir.
    Her ikisini de desteklemek için ortak bir get() yardımcısı kullanılır.
    """
    def cfg(key, default=None):
        # Flask'ın app.config nesnesi dict-benzeri (['KEY'] / .get()) çalışır;
        # DevelopmentConfig gibi düz bir sınıf ise nokta erişimi (getattr) gerekir.
        try:
            return app_config[key]
        except (TypeError, KeyError):
            return getattr(app_config, key, default)

    provider = (cfg("AI_PROVIDER", "gemini") or "gemini").lower()
    timeout = cfg("AI_REQUEST_TIMEOUT", 30)

    if provider == "gemini":
        return GeminiProvider(
            api_key=cfg("GEMINI_API_KEY", ""),
            model=cfg("GEMINI_MODEL", "gemini-3.5-flash"),
            timeout=timeout,
        )
    if provider == "openai":
        return OpenAIProvider(
            api_key=cfg("OPENAI_API_KEY", ""),
            model=cfg("OPENAI_MODEL", "gpt-4o-mini"),
            timeout=timeout,
        )
    if provider == "anthropic":
        return AnthropicProvider(
            api_key=cfg("ANTHROPIC_API_KEY", ""),
            model=cfg("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            timeout=timeout,
        )
    if provider == "ollama":
        return OllamaProvider(
            base_url=cfg("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=cfg("OLLAMA_MODEL", "llama3.1"),
            timeout=timeout,
        )

    raise ValueError(
        f"Bilinmeyen AI_PROVIDER: '{provider}'. "
        f"Geçerli seçenekler: gemini, openai, anthropic, ollama."
    )
