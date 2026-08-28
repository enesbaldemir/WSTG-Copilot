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


def get_ai_provider(app_config, overrides=None):
    """
    Sağlayıcı seçimi üç kademeli öncelik sırasıyla çözülür:

      1) `overrides` -- kullanıcının tarayıcıdan "kendi API key'imle kullan"
         (BYOK) diyerek gönderdiği { 'provider', 'api_key', 'model',
         'base_url' } değerleri. Verilirse hem DB'deki hem de .env'deki
         ayarların ÖNÜNE geçer ve HİÇBİR YERE KAYDEDİLMEZ; sadece o tek
         istek için kullanılır. Bu sayede birden çok kullanıcı, aynı
         kurulumu paylaşsa bile, istedikleri sağlayıcıyı/modeli kendi
         key'leriyle kullanabilir.
      2) DB'deki 'AIProviderSetting.is_active=True' kaydı (uygulama içindeki
         AI Ayarları panelinden yönetilir, sunucuda şifreli saklanır --
         paylaşılan/varsayılan kurulum için).
      3) app_config.AI_PROVIDER üzerinden .env fallback'i.

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

    timeout = cfg("AI_REQUEST_TIMEOUT", 30)

    overrides = overrides or {}
    override_provider = (overrides.get("provider") or "").strip().lower() or None
    override_key = (overrides.get("api_key") or "").strip() or None
    override_model = (overrides.get("model") or "").strip() or None
    override_base_url = (overrides.get("base_url") or "").strip() or None

    # 1) BYOK: kullanıcı en azından provider + (key ya da ollama için base_url)
    #    belirtmişse, bu isteğe özel sağlayıcıyı kur ve hiçbir şeyi kalıcı
    #    olarak değiştirme / kaydetme.
    if override_provider and (override_key or override_provider == "ollama"):
        return _build_provider(
            override_provider,
            api_key=override_key,
            model=override_model,
            base_url=override_base_url,
            timeout=timeout,
        )

    # 2) Paylaşılan/varsayılan kurulum: DB'de aktif işaretli sağlayıcı.
    db_provider = _from_db_setting(app_config, timeout)
    if db_provider is not None:
        return db_provider

    # 3) .env fallback.
    provider = (cfg("AI_PROVIDER", "gemini") or "gemini").lower()
    return _build_provider(
        provider,
        api_key=cfg(f"{provider.upper()}_API_KEY", ""),
        model=cfg(f"{provider.upper()}_MODEL", DEFAULT_MODELS.get(provider)),
        base_url=cfg("OLLAMA_BASE_URL", "http://localhost:11434"),
        timeout=timeout,
    )
