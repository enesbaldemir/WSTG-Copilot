from .gemini_provider import GeminiProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .ollama_provider import OllamaProvider

DEFAULT_MODELS = {
    "gemini": "gemini-3.7-flash",
    "openai": "gpt-5.6-terra",
    "anthropic": "claude-sonnet-5",
    "ollama": "llama3.1",
}


def _build_provider(provider, api_key, model, base_url, timeout):
    if provider == "gemini":
        return GeminiProvider(api_key=api_key or "", model=model or DEFAULT_MODELS["gemini"], timeout=timeout)
    if provider == "openai":
        return OpenAIProvider(api_key=api_key or "", model=model or DEFAULT_MODELS["openai"], timeout=timeout)
    if provider == "anthropic":
        return AnthropicProvider(api_key=api_key or "", model=model or DEFAULT_MODELS["anthropic"], timeout=timeout)
    if provider == "ollama":
        return OllamaProvider(
            base_url=base_url or "http://localhost:11434",
            model=model or DEFAULT_MODELS["ollama"],
            timeout=timeout,
        )
    raise ValueError(
        f"Bilinmeyen AI_PROVIDER: '{provider}'. "
        f"Geçerli seçenekler: gemini, openai, anthropic, ollama."
    )


def _from_db_setting(app_config, timeout):
    """DB'de aktif isaretlenmis bir AIProviderSetting varsa onu kullan.
    Yoksa (hic sağlayici eklenmemis, hicbiri aktif degil, ya da Flask app
    context/DB henuz hazir degil -- ör. ai/ katmaninin izole unit testleri)
    sessizce None doner ve cagiran taraf .env/app_config fallback'ine gecer.
    Bu, A.4'teki 'UI birincil yol, .env fallback olarak kalir' karariyla
    birebir uyumlu."""
    try:
        from models import AIProviderSetting
        import crypto_utils

        setting = AIProviderSetting.query.filter_by(is_active=True).first()
        if not setting:
            return None
        api_key = crypto_utils.decrypt(app_config, setting.api_key_encrypted) if setting.api_key_encrypted else ""
        return _build_provider(setting.provider, api_key, setting.model, setting.base_url, timeout)
    except Exception:
        return None


def get_ai_provider(app_config):
    """
    Once DB'deki 'AIProviderSetting.is_active=True' kaydina bakar (uygulama
    icindeki AI Ayarlari panelinden yonetilir); yoksa app_config.AI_PROVIDER
    uzerinden .env fallback'ine doner. Ust katmanlar (routes, ai analiz
    fonksiyonlari) hep bu fonksiyonu cagirir; sağlayici degisince baska
    hicbir yeri degistirmeye gerek yoktur.

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

    timeout = cfg("AI_REQUEST_TIMEOUT", 30)

    db_provider = _from_db_setting(app_config, timeout)
    if db_provider is not None:
        return db_provider

    provider = (cfg("AI_PROVIDER", "gemini") or "gemini").lower()
    return _build_provider(
        provider,
        api_key=cfg(f"{provider.upper()}_API_KEY", ""),
        model=cfg(f"{provider.upper()}_MODEL", DEFAULT_MODELS.get(provider)),
        base_url=cfg("OLLAMA_BASE_URL", "http://localhost:11434"),
        timeout=timeout,
    )
