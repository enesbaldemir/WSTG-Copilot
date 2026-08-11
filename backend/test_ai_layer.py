"""
Sandbox disari API'lere erisemedigi icin requests.post mocklanarak
mutlu senaryo (basarili cagri) dogrulanir. Gercek key ile calisirken
ayni kod yolu gercek HTTP istegi yapacaktir.
"""
from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, '.')

from ai.gemini_provider import GeminiProvider
from ai.openai_provider import OpenAIProvider
from ai.anthropic_provider import AnthropicProvider


def fake_response(json_data, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = json_data
    r.text = str(json_data)
    return r


def test_gemini_happy_path():
    provider = GeminiProvider(api_key="fake-key", model="gemini-3.5-flash", timeout=5)
    assert provider.is_configured() is True

    mock_json = {
        "candidates": [{"content": {"parts": [{"text": "Merhaba, ben Gemini!"}]}}]
    }
    with patch("ai.gemini_provider.requests.Session.post", return_value=fake_response(mock_json)) as mock_post:
        result = provider.chat(system_prompt="Kisa cevap ver.", user_prompt="Selam")
        assert result.text == "Merhaba, ben Gemini!"
        assert result.provider == "gemini"
        assert result.latency_ms >= 0
        assert mock_post.called
        sent_url = mock_post.call_args[0][0]
        assert "fake-key" in sent_url
    print("OK: gemini happy path")


def test_gemini_error_path():
    provider = GeminiProvider(api_key="fake-key", model="gemini-3.5-flash", timeout=5)
    with patch("ai.gemini_provider.requests.Session.post", return_value=fake_response({"error": "boom"}, status=500)):
        try:
            provider.chat(system_prompt="", user_prompt="x")
            raise AssertionError("should have raised")
        except Exception as e:
            assert "500" in str(e)
    print("OK: gemini error path raises AIRequestError with status code")


def test_gemini_not_configured():
    provider = GeminiProvider(api_key="", model="gemini-3.5-flash")
    assert provider.is_configured() is False
    try:
        provider.chat(system_prompt="", user_prompt="x")
        raise AssertionError("should have raised AIConfigError")
    except Exception as e:
        assert "eksik" in str(e) or "key" in str(e).lower()
    print("OK: gemini not-configured raises AIConfigError")


def test_openai_happy_path():
    provider = OpenAIProvider(api_key="fake", model="gpt-4o-mini", timeout=5)
    mock_json = {"choices": [{"message": {"content": "Merhaba, ben GPT!"}}]}
    with patch("ai.openai_provider.requests.post", return_value=fake_response(mock_json)):
        result = provider.chat(system_prompt="sys", user_prompt="Selam")
        assert result.text == "Merhaba, ben GPT!"
        assert result.provider == "openai"
    print("OK: openai happy path")


def test_anthropic_happy_path():
    provider = AnthropicProvider(api_key="fake", model="claude-sonnet-4-6", timeout=5)
    mock_json = {"content": [{"type": "text", "text": "Merhaba, ben Claude!"}]}
    with patch("ai.anthropic_provider.requests.post", return_value=fake_response(mock_json)):
        result = provider.chat(system_prompt="sys", user_prompt="Selam")
        assert result.text == "Merhaba, ben Claude!"
        assert result.provider == "anthropic"
    print("OK: anthropic happy path")


def test_factory_dict_and_class_config():
    from ai.factory import get_ai_provider

    class FakeClassConfig:
        AI_PROVIDER = "gemini"
        GEMINI_API_KEY = "k"
        GEMINI_MODEL = "gemini-3.5-flash"
        AI_REQUEST_TIMEOUT = 10

    p1 = get_ai_provider(FakeClassConfig)
    assert p1.name == "gemini" and p1.api_key == "k"

    dict_config = {
        "AI_PROVIDER": "openai",
        "OPENAI_API_KEY": "k2",
        "OPENAI_MODEL": "gpt-4o-mini",
        "AI_REQUEST_TIMEOUT": 10,
    }
    p2 = get_ai_provider(dict_config)
    assert p2.name == "openai" and p2.api_key == "k2"
    print("OK: factory works with both class-style and dict-style (Flask app.config) configs")


if __name__ == "__main__":
    test_gemini_happy_path()
    test_gemini_error_path()
    test_gemini_not_configured()
    test_openai_happy_path()
    test_anthropic_happy_path()
    test_factory_dict_and_class_config()
    print("\nAll AI-layer unit tests passed.")
