# meta developer: @CoderHoly
"""
⣿⣿⡻⠿⣳⠸⢿⡇⢇⣿⡧⢹⠿⣿⣿⣿⣿⣾⣿⡇⣿⣿⣿⣿⡿⡐⣯⠁ ⠄⠄
⠟⣛⣽⡳⠼⠄⠈⣷⡾⣥⣱⠃⠣⣿⣿⣿⣯⣭⠽⡇⣿⣿⣿⣿⣟⢢⠏⠄ ⠄
⢠⡿⠶⣮⣝⣿⠄⠄⠈⡥⢭⣥⠅⢌⣽⣿⣻⢶⣭⡿⠿⠜⢿⣿⣿⡿⠁⠄⠄
⠄⣼⣧⠤⢌⣭⡇⠄⠄⠄⠭⠭⠭⠯⠴⣚⣉⣛⡢⠭⠵⢶⣾⣦⡍⠁⠄⠄⠄⠄
⠄⣿⣷⣯⣭⡷⠄⠄⢀⣀⠩⠍⢉⣛⣛⠫⢏⣈⣭⣥⣶⣶⣦⣭⣛⠄⠄⠄⠄⠄
⢀⣿⣿⣿⡿⠃⢀⣴⣿⣿⣿⣎⢩⠌⣡⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠄⠄⠄
⢸⡿⢟⣽⠎⣰⣿⣿⣿⣿⣿⣿⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠄⠄
⣰⠯⣾⢅⣼⣿⣿⣿⣿⣿⣿⡇⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠄
⢰⣄⡉⣼⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠄
⢯⣌⢹⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄
⢸⣇⣽⣿⣿⣿⣿⣿⣿⣿⣿⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄
⢸⣟⣧⡻⣿⣿⣿⣿⣿⣿⣿⣧⡻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄
⠈⢹⡧⣿⣸⠿⢿⣿⣿⣿⣿⡿⠗⣈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠄
⠄⠘⢷⡳⣾⣷⣶⣶⣶⣶⣶⣾⣿⣿⢀⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠄
⠄⠄⠈⣵⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠄⠄
⠄⠄⠄⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠄⠄
"""


import json, os, re, base64, zlib, hashlib, tempfile, asyncio, logging

import httpx
from telethon.tl.types import Message

from .. import loader, utils
from ..inline.types import InlineCall

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)

__version__ = (3, 0, 0)

# ── Fallback prompts (used when Readme is absent) ──────────────────────────────────

_FALLBACK_ANALYSIS = """You are a cybersecurity expert analyzing a Python module for Hikka/Heroku Telegram userbot.

Rules:
- Respond ONLY with valid JSON, no markdown blocks, no extra text
- Analyze what the module does, list ALL commands (functions ending with 'cmd')
- Remove 'cmd' suffix from command names (timercmd -> timer)
- List ALL capabilities (features, background tasks, API usage, watchers)

Risk scale:
1. "Dangerous module ⚠️" — steals sessions, deletes account, obfuscated malware, sends data to unknown servers
2. "At your own risk 👨‍💻" — spam, mass actions, aggressive parsing
3. "Can be installed ✅" — safe utilities, informational commands

Normal safe API: loader.Module, @loader.tds, utils.answer, self.config, message.edit, httpx, inline buttons, tempfile

Format:
{"status": "...", "purpose": "purpose without commands list", "items": [{"type": "command", "name": "cmd_name", "description": "..."}, {"type": "capability", "description": "..."}], "dangerous_actions": false, "hidden_threats": false}

IMPORTANT: Find ALL cmd functions, remove 'cmd' suffix in name. Speak Russian."""

_FALLBACK_QUESTION = """You are an expert Python developer. Explain the module in simple terms.

Rules:
- Answer in Russian, concise
- Explain commands (with . prefix) and how to use them
- Use ONLY Telegram HTML: <b>, <code>, <i>, <blockquote>
- No Markdown, no emoji spam

Format: <code>.rf</code> — analyze files. <b>Important:</b> file must be .py"""

# ── Provider Manager ────────────────────────────────────────────────────────────────

_TIER = {"free": "🟢", "paid": "🔵", "unknown": "🟡"}

_BUILTIN_PROVIDERS = {
    "groq": {
        "label": "Groq",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "models_url": "https://api.groq.com/openai/v1/models",
        "key_cfg": "groq_api_key",
        "tier": "free",
    },
    "openai": {
        "label": "OpenAI",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "models_url": "https://api.openai.com/v1/models",
        "key_cfg": "openai_api_key",
        "tier": "paid",
    },
    "gemini": {
        "label": "Gemini",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "models_url": "https://generativelanguage.googleapis.com/v1beta/openai/models",
        "key_cfg": "gemini_api_key",
        "tier": "free",
        "models_fallback": "gemini",
    },
    "xai": {
        "label": "XAI (Grok)",
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "models_url": "https://api.x.ai/v1/models",
        "key_cfg": "xai_api_key",
        "tier": "paid",
    },
    "openrouter": {
        "label": "OpenRouter",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "models_url": "https://openrouter.ai/api/v1/models",
        "key_cfg": "openrouter_api_key",
        "tier": "free",
    },
    "nvidia": {
        "label": "NVIDIA NIM",
        "endpoint": "https://integrate.api.nvidia.com/v1/chat/completions",
        "models_url": None,
        "key_cfg": "nvidia_api_key",
        "tier": "free",
        "models_fallback": "nvidia",
    },
    "cerebras": {
        "label": "Cerebras",
        "endpoint": "https://api.cerebras.ai/v1/chat/completions",
        "models_url": "https://api.cerebras.ai/v1/models",
        "key_cfg": "cerebras_api_key",
        "tier": "paid",
    },
    "huggingface": {
        "label": "HuggingFace",
        "endpoint": "https://api-inference.huggingface.co/v1/chat/completions",
        "models_url": None,
        "key_cfg": "huggingface_api_key",
        "tier": "free",
        "models_fallback": "huggingface",
    },
}

_FALLBACK_MODELS = {
    "gemini": [
        {"id": "gemini-2.0-flash", "label": "Gemini 2.0 Flash", "ctx": "1M"},
        {"id": "gemini-2.0-flash-lite", "label": "Gemini 2.0 Flash Lite", "ctx": "1M"},
        {"id": "gemini-1.5-flash", "label": "Gemini 1.5 Flash", "ctx": "1M"},
        {"id": "gemini-1.5-flash-8b", "label": "Gemini 1.5 Flash 8B", "ctx": "1M"},
        {"id": "gemini-1.5-pro", "label": "Gemini 1.5 Pro", "ctx": "1M"},
    ],
    "nvidia": [
        {"id": "nvidia/llama-3.1-nemotron-70b-instruct", "label": "Nemotron 70B", "ctx": "128K"},
        {"id": "nvidia/llama-3.3-nemotron-super-49b", "label": "Nemotron Super 49B", "ctx": "128K"},
        {"id": "mistralai/mistral-7b-instruct-v0.3", "label": "Mistral 7B", "ctx": "32K"},
        {"id": "google/gemma-2-2b-it", "label": "Gemma 2 2B", "ctx": "8K"},
        {"id": "meta/llama-3.1-8b-instruct", "label": "Llama 3.1 8B", "ctx": "128K"},
        {"id": "meta/llama-3.1-70b-instruct", "label": "Llama 3.1 70B", "ctx": "128K"},
    ],
    "huggingface": [
        {"id": "microsoft/Phi-3.5-mini-instruct", "label": "Phi-3.5 Mini", "ctx": "128K"},
        {"id": "microsoft/Phi-3.5-vision-instruct", "label": "Phi-3.5 Vision", "ctx": "128K"},
        {"id": "meta-llama/Llama-3.2-3B-Instruct", "label": "Llama 3.2 3B", "ctx": "128K"},
        {"id": "mistralai/Mistral-7B-Instruct-v0.3", "label": "Mistral 7B", "ctx": "32K"},
        {"id": "HuggingFaceH4/zephyr-7b-beta", "label": "Zephyr 7B", "ctx": "16K"},
        {"id": "google/gemma-2-2b-it", "label": "Gemma 2 2B", "ctx": "8K"},
    ],
}


class ProviderManager:
    def __init__(self, config):
        self._config = config

    @property
    def active(self) -> str:
        return self._config["provider"]

    def builtin_ids(self) -> list[str]:
        return list(_BUILTIN_PROVIDERS)

    def _custom(self) -> dict:
        raw = self._config.get("custom_providers", "{}")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    def all_ids(self) -> list[str]:
        return list(_BUILTIN_PROVIDERS) + list(self._custom())

    def info(self, provider: str = None) -> dict:
        p = provider or self.active
        if p in _BUILTIN_PROVIDERS:
            return _BUILTIN_PROVIDERS[p]
        custom = self._custom().get(p)
        if custom:
            return {"label": p, "endpoint": custom["url"], "models_url": None, "key_cfg": None, "_custom_key": custom["api_key"], "tier": "unknown"}
        raise ValueError(f"Unknown provider: {p}")

    def api_key(self, provider: str = None) -> str:
        p = provider or self.active
        info = self.info(p)
        key_cfg = info.get("key_cfg")
        if key_cfg:
            return self._config.get(key_cfg, "")
        return info.get("_custom_key", "")


# ── AI Client ──────────────────────────────────────────────────────────────────────

_HTTP_ERRORS = {
    401: "Неверный API ключ. Проверьте настройки: .cfg ReadFileMod",
    402: "Недостаточно средств на балансе провайдера",
    429: "Слишком много запросов. Повторите через минуту",
}


class AiClient:
    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=120)
        return self._client

    async def chat(self, endpoint: str, api_key: str, model: str, sys: str, user: str) -> str:
        client = await self._get_client()
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": sys},
                {"role": "user", "content": user[:20000]},
            ],
        }
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

        try:
            resp = await client.post(endpoint, headers=headers, json=payload)
        except httpx.ConnectError:
            raise ConnectionError("Не удалось подключиться к API провайдера")
        except httpx.TimeoutException:
            raise ConnectionError("Таймаут запроса к API провайдера")

        code = resp.status_code
        msg = _HTTP_ERRORS.get(code)
        if msg:
            raise ConnectionError(msg)
        if code >= 500:
            raise ConnectionError(f"Провайдер временно недоступен (HTTP {code})")
        if code != 200:
            body = (resp.text or "")[:200]
            raise ConnectionError(f"Ошибка API (HTTP {code}): {body}")

        try:
            data = resp.json()
        except ValueError:
            raise ConnectionError("Некорректный JSON ответ от API")

        text = (data.get("choices") or [{}])[0].get("message", {}).get("content")
        if not text:
            raise ConnectionError("Пустой ответ от модели")
        return text.strip()

    async def fetch_models(self, url: str, api_key: str) -> list[dict] | None:
        if not url:
            return None
        client = await self._get_client()
        try:
            resp = await client.get(url, headers={"Authorization": f"Bearer {api_key}"})
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            raise ConnectionError(f"Не удалось получить список моделей: {e}")

        out = []
        for m in data.get("data", []):
            mid = m.get("id", "")
            ctx = m.get("context_length") or 0
            out.append({
                "id": mid,
                "label": m.get("name", mid),
                "ctx": f"{ctx // 1024}K" if ctx else "?",
            })
        out.sort(key=lambda x: x["id"])
        return out

    async def close(self):
        if self._client:
            await self._client.aclose()


# ── Analyzer Core ──────────────────────────────────────────────────────────────────

_THREAT_PATTERNS = [
    (re.compile(r"export_session_string", re.I), "Экспорт сессии (угон аккаунта)"),
    (re.compile(r"DeleteAccountRequest", re.I), "Удаление аккаунта"),
    (re.compile(r"ResetAuthorizationRequest", re.I), "Сброс всех сессий"),
    (re.compile(r"edit_2fa|edit_cloud_password", re.I), "Смена пароля 2FA"),
    (re.compile(r"terminate_all_sessions", re.I), "Завершение всех сессий"),
    (re.compile(r"os\.system|subprocess\.(Popen|call)", re.I), "Выполнение системных команд"),
    (re.compile(r"socket\.socket", re.I), "Создание сокетов"),
    (re.compile(r"\.session", re.I), "Работа с .session файлом"),
    (re.compile(r"os\.environ", re.I), "Чтение переменных окружения"),
    (re.compile(r"for.*send_message|while.*send_message", re.I), "Массовая рассылка (спам)"),
]

_B64_ZLIB_RE = re.compile(r"b'([A-Za-z0-9+/=]{50,})'")


class AnalyzerCore:
    def decode(self, code: str) -> str:
        m = _B64_ZLIB_RE.search(code)
        if not m:
            return code
        try:
            raw = base64.b64decode(m.group(1))
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                pass
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return code

    def threats(self, code: str) -> list[dict]:
        found = []
        for pat, desc in _THREAT_PATTERNS:
            if pat.search(code):
                found.append({"description": desc})
        return found


# ── Cache Manager ──────────────────────────────────────────────────────────────────

class CacheManager:
    def __init__(self):
        self._dir = os.path.join(tempfile.gettempdir(), "readfilemod_cache")
        os.makedirs(self._dir, exist_ok=True)

    def _path(self, content: str) -> str:
        h = hashlib.sha256(content.encode()).hexdigest()
        return os.path.join(self._dir, f"{h}.json")

    def get(self, content: str) -> dict | None:
        path = self._path(content)
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def set(self, content: str, data: dict):
        try:
            with open(self._path(content), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
        except Exception:
            pass

    def stats(self) -> tuple[int, int]:
        total, count = 0, 0
        if os.path.isdir(self._dir):
            for fname in os.listdir(self._dir):
                fpath = os.path.join(self._dir, fname)
                try:
                    total += os.path.getsize(fpath)
                    count += 1
                except OSError:
                    pass
        return total, count

    def clear(self) -> int:
        removed = 0
        if os.path.isdir(self._dir):
            for fname in os.listdir(self._dir):
                try:
                    os.remove(os.path.join(self._dir, fname))
                    removed += 1
                except Exception:
                    pass
        return removed


# ── UI Builder ─────────────────────────────────────────────────────────────────────

def _fmt_size(b: int) -> str:
    if b >= 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    if b >= 1024:
        return f"{b // 1024} KB"
    return f"{b} B"


def _chunks(text: str, size: int) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)]


class UIBuilder:
    @staticmethod
    async def show_page(mod, target, chunks, info, index):
        if not chunks:
            text = "Файл пуст."
            buttons = [[{"text": "✖", "action": "close"}]]
        else:
            total = len(chunks)
            index = max(0, min(index, total - 1))
            text = (
                f"<b>{info.get('name', '?')}</b> — {_fmt_size(info.get('size', 0))}\n"
                f"<i>Страница {index + 1}/{total}</i>\n\n"
                f"<pre>{utils.escape_html(chunks[index])}</pre>"
            )
            buttons = [
                [
                    {"text": "◀", "callback": mod._page_cb, "args": (index - 1,)},
                    {"text": "▶", "callback": mod._page_cb, "args": (index + 1,)},
                ],
                [{"text": "Анализ AI", "callback": mod._info_cb, "args": (index,)}],
                [{"text": "Закрыть", "action": "close"}],
            ]
        if isinstance(target, Message):
            await mod.inline.form(text=text, message=target, reply_markup=buttons)
        elif hasattr(target, "edit"):
            await target.edit(text=text, reply_markup=buttons)

    @staticmethod
    async def show_providers(mod, target):
        provs = mod._providers
        cur = provs.active

        has_keyscanner = bool(getattr(mod, "_ks_ref", None))
        has_config_key = {pid: bool(provs.api_key(pid)) for pid in provs.all_ids()}

        text = (
            "<b>Выберите провайдера AI</b>\n\n"
            "🟢 — бесплатные\n🔵 — платные\n🟡 — кастомные (неизвестно)\n\n"
        )

        if has_keyscanner:
            text += "<i>Показаны провайдеры с ключами (KeyScanner)</i>\n\n"
        else:
            text += "<i>Рекомендую: .fheta KeyScanner</i>\n\n"

        buttons = []
        for pid in provs.all_ids():
            has_ks = pid in getattr(mod, "_ks_provider_models", {})
            has_cfg = has_config_key.get(pid, False)

            # Filter: if KeyScanner detected, only show providers with keys
            if has_keyscanner and not has_ks and not has_cfg:
                continue

            info = provs.info(pid)
            label = info["label"]
            tier = info.get("tier", "unknown")
            emoji = _TIER.get(tier, "🟡")
            active = pid == cur
            key_mark = " 🔑" if (has_ks or has_cfg) else ""
            buttons.append([
                {"text": f"{'✓ ' if active else ''}{emoji} {label}{key_mark}",
                 "callback": mod._select_prov_cb, "args": (pid,)}
            ])

        if not buttons:
            text += "<i>Нет доступных провайдеров. Установите KeyScanner: .fheta KeyScanner</i>\n"

        buttons.append([{"text": "← Настройки", "callback": mod._show_settings}])
        buttons.append([{"text": "Закрыть", "action": "close"}])
        if isinstance(target, Message):
            await mod.inline.form(text=text, message=target, reply_markup=buttons)
        else:
            await target.edit(text=text, reply_markup=buttons)

    @staticmethod
    async def show_models(mod, target, models, page: int, pid: str):
        per_page = 5
        total = len(models)
        pages = max(1, (total + per_page - 1) // per_page)
        page = max(0, min(page, pages - 1))
        start = page * per_page
        batch = models[start:start + per_page]

        info = mod._providers.info(pid)
        text = (
            f"<b>{info['label']}</b> — <i>{total} моделей</i>\n"
            f"Страница {page + 1}/{pages}\n\n"
        )
        prefix = mod._get_prefix()
        for m in batch:
            text += (
                f"<code>{m['id']}</code>\n"
                f"<blockquote>Контекст: {m.get('ctx', '?')}\n"
                f"Установить: <code>{prefix}fcfg ReadFileMod model {m['id']}</code></blockquote>\n\n"
            )

        nav = []
        if page > 0:
            nav.append({"text": "◀", "callback": mod._models_page_cb, "args": (page - 1, pid)})
        if page < pages - 1:
            nav.append({"text": "▶", "callback": mod._models_page_cb, "args": (page + 1, pid)})
        buttons = [nav] if nav else []
        buttons.append([{"text": "← К провайдерам", "callback": mod._back_providers_cb}])
        buttons.append([{"text": "← Настройки", "callback": mod._show_settings}])
        buttons.append([{"text": "Закрыть", "action": "close"}])

        if isinstance(target, Message):
            await mod.inline.form(text=text, message=target, reply_markup=buttons)
        else:
            await target.edit(text=text, reply_markup=buttons)

    @staticmethod
    def analysis_text(data: dict, info: dict, model: str) -> str:
        status = data.get("status", "Ошибка")
        purpose = data.get("purpose", "")
        items = data.get("items", [])

        text = (
            f"<b>{info.get('name', '?')}</b> — {_fmt_size(info.get('size', 0))}\n"
            f"<i>Модель: {model}</i>\n\n"
            f"<b>Статус:</b> {status}\n\n"
        )
        if purpose:
            text += f"<b>Назначение:</b>\n<blockquote>{utils.escape_html(purpose)}</blockquote>\n"
        if items:
            text += "\n<b>Команды и возможности:</b>\n<blockquote>"
            for item in items:
                if item.get("type") == "command":
                    text += f"• <code>.{item['name']}</code> — {utils.escape_html(item.get('description', ''))}\n"
                elif item.get("type") == "capability":
                    text += f"△ {utils.escape_html(item.get('description', ''))}\n"
            text += "</blockquote>"
        return text

    @staticmethod
    def error_text(err: str, info: dict, model: str) -> str:
        return (
            f"<b>{info.get('name', '?')}</b> — {_fmt_size(info.get('size', 0))}\n"
            f"<i>Модель: {model}</i>\n\n"
            f"<b>Ошибка анализа</b>\n"
            f"<blockquote>{utils.escape_html(err)}</blockquote>"
        )

    @staticmethod
    async def show_analysis(mod, target, data, info, model):
        text = UIBuilder.analysis_text(data, info, model)
        buttons = [
            [{"text": "Задать вопрос", "callback": mod._ask_cb}],
            [{"text": "Сменить провайдера", "callback": mod._back_providers_cb}],
            [{"text": "← К коду", "callback": mod._page_cb, "args": (0,)}],
            [{"text": "Закрыть", "action": "close"}],
        ]
        if isinstance(target, Message):
            await mod.inline.form(text=text, message=target, reply_markup=buttons)
        elif hasattr(target, "edit"):
            await target.edit(text=text, reply_markup=buttons)


# ── Main Module ────────────────────────────────────────────────────────────────────

@loader.tds
class ReadFileMod(loader.Module):
    """Анализ Python-модулей через AI (поддержка Groq, OpenAI, Gemini, XAI)"""

    strings = {"name": "ReadFileMod"}

    def __init__(self):
        self.config = loader.ModuleConfig(
            loader.ConfigValue("provider", "groq", "Провайдер AI (нажми чтобы выбрать)", validator=loader.validators.Choice(["groq", "openai", "gemini", "xai", "openrouter", "nvidia", "cerebras", "huggingface"])),
            loader.ConfigValue("model", "llama-3.3-70b-versatile", "Модель для анализа"),
            loader.ConfigValue("groq_api_key", "", "Ключ Groq", validator=loader.validators.Hidden()),
            loader.ConfigValue("openai_api_key", "", "Ключ OpenAI", validator=loader.validators.Hidden()),
            loader.ConfigValue("gemini_api_key", "", "Ключ Gemini", validator=loader.validators.Hidden()),
            loader.ConfigValue("xai_api_key", "", "Ключ XAI (Grok)", validator=loader.validators.Hidden()),
            loader.ConfigValue("openrouter_api_key", "", "Ключ OpenRouter", validator=loader.validators.Hidden()),
            loader.ConfigValue("nvidia_api_key", "", "Ключ NVIDIA NIM", validator=loader.validators.Hidden()),
            loader.ConfigValue("cerebras_api_key", "", "Ключ Cerebras", validator=loader.validators.Hidden()),
            loader.ConfigValue("huggingface_api_key", "", "Ключ HuggingFace", validator=loader.validators.Hidden()),
            loader.ConfigValue("custom_providers", "{}", "Кастомные провайдеры (JSON)", validator=loader.validators.Hidden()),
        )
        self._providers = ProviderManager(self.config)
        self._ai = AiClient()
        self._analyzer = AnalyzerCore()
        self._cache = CacheManager()
        self._ui = UIBuilder()
        self._user_data: dict[int, dict] = {}
        self._prompts: dict[str, str] = {}
        self._ks_ref = None
        self._ks_key_count = 0
        self._ks_matched = 0
        self._ks_scanned = False
        self._ks_provider_models: dict[str, list[dict]] = {}

    async def client_ready(self):
        try:
            readme = os.path.join(os.path.dirname(__file__), "Readme")
            if os.path.exists(readme):
                with open(readme, encoding="utf-8") as f:
                    self._prompts = self._parse_readme(f.read())
        except Exception:
            pass
        if not self._prompts.get("analysis"):
            self._prompts["analysis"] = _FALLBACK_ANALYSIS
        if not self._prompts.get("question"):
            self._prompts["question"] = _FALLBACK_QUESTION

        try:
            self._ks_ref = self.lookup("KeyScanner")
        except Exception:
            self._ks_ref = None
        if self._ks_ref:
            asyncio.create_task(self._delayed_key_scan())

    @staticmethod
    def _get_prefix():
        try:
            from .. import utils
            if hasattr(utils, 'get_prefix'):
                return (utils.get_prefix() or ".").strip()
        except Exception:
            pass
        return "."

    @staticmethod
    def _parse_readme(text: str) -> dict:
        prompts = {}
        section, lines = None, []
        for line in text.split("\n"):
            m = re.match(r"\[(\w+)\]", line)
            if m:
                if section:
                    prompts[section] = "\n".join(lines).strip()
                section = m.group(1)
                lines = []
            elif section:
                lines.append(line)
        if section:
            prompts[section] = "\n".join(lines).strip()
        return prompts

    def _udata(self, uid: int) -> dict:
        if uid not in self._user_data:
            self._user_data[uid] = {"content": "", "path": "", "chunks": [], "info": {}, "count": 0}
        return self._user_data[uid]

    def _clean_udata(self, uid: int):
        d = self._user_data.pop(uid, None)
        if d and d.get("path") and os.path.exists(d["path"]):
            try:
                os.remove(d["path"])
            except Exception:
                pass

    async def _scan_keyscanner(self):
        if self._ks_scanned or not self._ks_ref:
            return
        self._ks_scanned = True
        try:
            keys = getattr(self._ks_ref, "_keys", {})
            self._ks_key_count = len(keys)
            if not keys:
                return
            for key, prov_name in keys.items():
                if prov_name in _BUILTIN_PROVIDERS:
                    cfg_key = _BUILTIN_PROVIDERS[prov_name].get("key_cfg")
                    if cfg_key and not self.config.get(cfg_key, ""):
                        self.config[cfg_key] = key
                        self._ks_matched += 1

            # Build provider→models map from KeyScanner's per-key model cache
            model_cache = getattr(self._ks_ref, "_model_cache", {})
            if isinstance(model_cache, dict):
                for key, prov_name in keys.items():
                    models = model_cache.get(key, [])
                    if not models:
                        continue
                    if prov_name not in self._ks_provider_models:
                        self._ks_provider_models[prov_name] = []
                    seen = {m["id"] for m in self._ks_provider_models[prov_name]}
                    for m in models:
                        mid = m.get("id", "") if isinstance(m, dict) else str(m)
                        if mid and mid not in seen:
                            seen.add(mid)
                            self._ks_provider_models[prov_name].append(
                                {"id": mid, "label": m.get("label", mid) if isinstance(m, dict) else mid, "ctx": m.get("ctx", "?") if isinstance(m, dict) else "?"}
                            )

            if self._ks_matched:
                logger.info(f"ReadFileMod: auto-filled {self._ks_matched} keys from KeyScanner")
        except Exception:
            pass

    async def _delayed_key_scan(self):
        await asyncio.sleep(3)
        await self._scan_keyscanner()

    async def _get_models(self, pid: str) -> list[dict]:
        prov_info = self._providers.info(pid)

        # 1. Try API fetch
        try:
            models = await self._ai.fetch_models(prov_info.get("models_url"), self._providers.api_key(pid) or "")
            if models:
                return models
        except Exception:
            pass

        # 2. Try KeyScanner model cache (already aggregated by provider)
        ks_models = self._ks_provider_models.get(pid, [])
        if ks_models:
            return ks_models

        # 3. Fallback to hardcoded list
        fb_key = prov_info.get("models_fallback")
        if fb_key and fb_key in _FALLBACK_MODELS:
            return _FALLBACK_MODELS[fb_key]

        return []

    # ── commands ──

    @loader.command(ru_doc="Ответьте на .py файл для AI анализа")
    async def rf(self, message: Message):
        reply = await message.get_reply_message()
        if not reply or not reply.file:
            await utils.answer(message, "Ответьте на .py файл")
            return

        uid = message.sender_id
        self._clean_udata(uid)
        ud = self._udata(uid)

        await utils.answer(message, f"Читаю {reply.file.name}...")

        try:
            path = await reply.download_media()
            if os.path.getsize(path) > 10 * 1024 * 1024:
                os.remove(path)
                await utils.answer(message, "Файл слишком большой (макс 10 MB)")
                return
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            await utils.answer(message, f"Ошибка чтения: {e}")
            return

        detected_code = self._analyzer.decode(content)
        if detected_code != content:
            content = detected_code

        name = self._extract_name(content, os.path.basename(path))
        ud["content"] = content
        ud["path"] = path
        ud["chunks"] = _chunks(content, 1500)
        ud["info"] = {"name": name, "size": os.path.getsize(path), "pages": len(ud["chunks"])}
        ud["count"] += 1

        await self._ui.show_page(self, message, ud["chunks"], ud["info"], 0)

    @staticmethod
    def _extract_name(content: str, filename: str) -> str:
        m = re.search(r"""strings\s*=\s*\{[^}]*["']name["']\s*:\s*["']([^"']+)["']""", content, re.DOTALL)
        if m:
            return m.group(1)
        m = re.search(r"class\s+(\w+)\s*\(\s*(?:loader\.)?Module\s*\)", content, re.I)
        if m:
            name = m.group(1)
            for suf in ("Module", "Mod"):
                if name.endswith(suf):
                    return name[:-len(suf)]
            return name
        return filename.replace(".py", "") if filename.endswith(".py") else filename

    @loader.command(ru_doc="Выбрать провайдера и модель AI")
    async def spai(self, message: Message):
        await self._ui.show_providers(self, message)

    @loader.command(ru_doc="Настройки модуля ReadFileMod")
    async def rfs(self, message: Message):
        await self._scan_keyscanner()
        await self._show_settings(message)

    async def _show_settings(self, target):
        prov = self._providers
        pid = prov.active
        info = prov.info(pid)
        tier_emoji = _TIER.get(info.get("tier", "unknown"), "🟡")

        text = "<b>⚙️ ReadFileMod Settings</b>\n\n"
        text += (
            f"<b>👤 Провайдер:</b> {info['label']} {tier_emoji}\n"
            f"<b>🤖 Модель:</b> <code>{self.config['model']}</code>\n\n"
        )

        key_line = ""
        configured = 0
        total = 0
        for pid2 in prov.builtin_ids():
            i = prov.info(pid2)
            cfg_key = i.get("key_cfg", "")
            has_key = bool(self.config.get(cfg_key, "")) if cfg_key else False
            key_line += "🟢" if has_key else "🔴"
            if has_key:
                configured += 1
            total += 1
        custom = prov._custom()
        if custom:
            key_line += "🟡" * len(custom)
            total += len(custom)

        text += "<b>🔑 Ключи:</b> " + key_line + "\n"
        text += f"Настроено: {configured}/{total}\n\n"

        if self._ks_ref:
            ks_prov_count = len(self._ks_provider_models)
            ks_model_count = sum(len(v) for v in self._ks_provider_models.values())
            text += (
                f"<b>🔄 KeyScanner:</b> {self._ks_key_count} ключей, "
                f"{self._ks_matched} подставлено\n"
                f"{ks_prov_count} провайдеров, {ks_model_count} моделей в кеше\n\n"
            )
        else:
            text += "<b>🔄 KeyScanner:</b> не обнаружен\n"
            text += "<i>Для поиска API ключей: .fheta KeyScanner</i>\n\n"

        total_analyzed = sum(d.get("count", 0) for d in self._user_data.values())
        total_b, total_f = self._cache.stats()

        text += "<b>📊 Статистика:</b>\n"
        text += f"Проанализировано: {total_analyzed}\n"
        text += f"Кеш: {_fmt_size(total_b)} ({total_f} файлов)"

        buttons = [
            [{"text": "👤 Провайдеры", "callback": self._back_providers_cb},
             {"text": "🤖 Модели", "callback": self._settings_models_cb}],
        ]
        if self._ks_ref and not self._ks_scanned:
            buttons.append([{"text": "🔄 Сканировать KeyScanner", "callback": self._settings_scan_cb}])
        buttons.append([{"text": "🗑 Очистить кеш", "callback": self._clean_cache_cb}])
        buttons.append([{"text": "✖ Закрыть", "action": "close"}])

        if isinstance(target, Message):
            await self.inline.form(text=text, message=target, reply_markup=buttons)
        elif hasattr(target, "edit"):
            await target.edit(text=text, reply_markup=buttons)

    @loader.command(ru_doc="Очистить кеш и временные файлы")
    async def cc(self, message: Message):
        total_b, total_f = self._cache.stats()
        text = (
            f"<b>Статистика кеша</b>\n\n"
            f"Занято: {_fmt_size(total_b)}\n"
            f"Файлов: {total_f}\n"
            f"Проанализировано: {sum(d['count'] for d in self._user_data.values())}"
        )
        buttons = [[{"text": "Очистить", "callback": self._clean_cache_cb}]]
        await self.inline.form(text=text, message=message, reply_markup=buttons)

    @loader.command(ru_doc="Добавить кастомный AI провайдер. Ответьте на сообщение с форматом:\nURL (https://...)\nApiKey (ключ)")
    async def addprovider(self, message: Message):
        reply = await message.get_reply_message()
        if not reply or not reply.text:
            await utils.answer(message, "Ответьте на сообщение с форматом:\nURL (https://...)\nApiKey (ключ)")
            return

        text = reply.text.strip()
        url_m = re.search(r"URL\s*\(([^)]+)\)", text)
        key_m = re.search(r"ApiKey\s*\(([^)]+)\)", text)
        if not url_m or not key_m:
            await utils.answer(message, "Неверный формат. Используйте:\nURL (https://...)\nApiKey (ключ)")
            return

        url = url_m.group(1).strip()
        api_key = key_m.group(1).strip()

        name_m = re.search(r"https?://([^.]+)", url)
        pname = name_m.group(1) if name_m else f"custom_{len(self._providers._custom()) + 1}"

        custom = json.loads(self.config["custom_providers"])
        custom[pname] = {"url": url, "api_key": api_key}
        self.config["custom_providers"] = json.dumps(custom)

        await utils.answer(message, f"Провайдер <code>{pname}</code> добавлен.\nИспользуйте: .cfg ReadFileMod provider {pname}")

    @loader.command(ru_doc="Проверить обновления модуля")
    async def updatef(self, message: Message):
        await utils.answer(message, "Проверка обновлений...")
        url = "https://raw.githubusercontent.com/Holy16rus/Module-Holy/main/ReadFileMod.py"
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(url)
                r.raise_for_status()
                m = re.search(r"__version__\s*=\s*\((\d+),\s*(\d+),\s*(\d+)\)", r.text)
                if not m:
                    await utils.answer(message, "Не удалось определить версию в репозитории")
                    return
                remote_ver = tuple(map(int, m.groups()))
                cur = __version__
                if remote_ver <= cur:
                    await self.inline.form(
                        text=f"<b>Версия:</b> {'.'.join(map(str, cur))}\n<b>Репо:</b> {'.'.join(map(str, remote_ver))}\n\nУ вас актуальная версия",
                        message=message,
                        reply_markup=[],
                    )
                    return
                await self.inline.form(
                    text=(
                        f"<b>Версия:</b> {'.'.join(map(str, cur))}\n"
                        f"<b>Репо:</b> {'.'.join(map(str, remote_ver))}\n\n"
                        "Обновить модуль?"
                    ),
                    message=message,
                    reply_markup=[[{"text": "Обновить", "callback": self._update_cb, "args": (r.text,)}]],
                )
        except Exception as e:
            await utils.answer(message, f"Ошибка: {e}")

    # ── callbacks ──

    async def _page_cb(self, call: InlineCall, index: int):
        uid = call.from_user.id
        ud = self._user_data.get(uid)
        if not ud or not ud.get("chunks"):
            await call.answer("Сессия устарела. Загрузите файл через .rf", show_alert=True)
            return
        await self._ui.show_page(self, call, ud["chunks"], ud["info"], index)

    async def _info_cb(self, call: InlineCall, _page: int):
        uid = call.from_user.id
        ud = self._user_data.get(uid)
        if not ud or not ud.get("content"):
            await call.edit("Содержимое файла потеряно. Загрузите заново через .rf")
            return

        await self._scan_keyscanner()

        cached = self._cache.get(ud["content"])
        if cached:
            await self._ui.show_analysis(self, call, cached, ud["info"], self.config["model"])
            return

        await call.edit("Анализирую модуль...")
        try:
            pid = self._providers.active
            info = self._providers.info(pid)
            key = self._providers.api_key(pid)
            if not key:
                suffix = ""
                if not self._ks_ref:
                    suffix = "\n\n<i>Для поиска API ключей рекомендую KeyScanner (.fheta KeyScanner)</i>"
                raise ConnectionError(f"Не настроен API ключ для {info['label']}. Используйте: .cfg ReadFileMod {info.get('key_cfg', '')}{suffix}")

            raw = await self._ai.chat(
                info["endpoint"], key, self.config["model"],
                self._prompts.get("analysis", _FALLBACK_ANALYSIS),
                ud["content"],
            )
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # try to extract JSON from the response
                extracted = re.search(r"\{.*\}", raw, re.DOTALL)
                if extracted:
                    data = json.loads(extracted.group())
                else:
                    raise ValueError(f"JSON не найден в ответе: {raw[:200]}")

            self._cache.set(ud["content"], data)
            await self._ui.show_analysis(self, call, data, ud["info"], self.config["model"])
        except Exception as e:
            err = _ufmt(str(e))
            await call.edit(
                self._ui.error_text(err, ud["info"], self.config["model"]),
                reply_markup=[
                    [{"text": "Сменить провайдера", "callback": self._back_providers_cb}],
                    [{"text": "Назад к коду", "callback": self._page_cb, "args": (0,)}],
                    [{"text": "Закрыть", "action": "close"}],
                ],
            )

    async def _ask_cb(self, call: InlineCall):
        uid = call.from_user.id
        ud = self._user_data.get(uid)
        if not ud or not ud.get("content"):
            await call.edit("Содержимое потеряно. Загрузите через .rf")
            return
        await call.edit(
            "<b>Задать вопрос о модуле</b>\n\nНапишите вопрос в поле ниже",
            reply_markup=[
                [{"text": "Задать вопрос", "input": "Введите вопрос", "handler": self._q_handler}],
                [{"text": "← К анализу", "callback": self._info_cb, "args": (0,)}],
            ],
        )

    async def _q_handler(self, call: InlineCall, question: str):
        if not question or not question.strip():
            await call.answer("Вопрос не может быть пустым", show_alert=True)
            return

        uid = call.from_user.id
        ud = self._user_data.get(uid)
        if not ud or not ud.get("content"):
            await call.edit("Содержимое потеряно.")
            return

        await self._scan_keyscanner()

        await call.edit("Обрабатываю вопрос...")

        try:
            pid = self._providers.active
            info = self._providers.info(pid)
            key = self._providers.api_key(pid)
            if not key:
                raise ConnectionError(f"Нет API ключа для {info['label']}")

            raw = await asyncio.wait_for(
                self._ai.chat(
                    info["endpoint"], key, self.config["model"],
                    self._prompts.get("question", _FALLBACK_QUESTION),
                    f"Вопрос: {question.strip()}\n\nКод модуля:\n{ud['content'][:20000]}",
                ),
                timeout=60,
            )
            clean = re.sub(r"[*_#]", "", raw).strip()
        except asyncio.TimeoutError:
            await call.edit("Время ожидания истекло. Попробуйте еще раз")
            return
        except Exception as e:
            await call.edit(f"Ошибка: {_ufmt(str(e))}")
            return

        await call.edit(
            f"<b>Вопрос:</b>\n<blockquote>{utils.escape_html(question)}</blockquote>\n\n"
            f"<b>Ответ:</b>\n<blockquote>{clean}</blockquote>",
            reply_markup=[
                [{"text": "Задать еще", "input": "Введите вопрос", "handler": self._q_handler}],
                [{"text": "← К анализу", "callback": self._info_cb, "args": (0,)}],
            ],
        )

    async def _select_prov_cb(self, call: InlineCall, pid: str):
        self.config["provider"] = pid
        prov_info = self._providers.info(pid)
        await call.answer(f"Выбран: {prov_info['label']}", show_alert=False)

        models = await self._get_models(pid)

        if not models:
            await call.edit(
                f"<b>{prov_info['label']}</b>\n\nНе удалось получить список моделей.\n"
                f"Проверьте API ключ или установите модель вручную: <code>.fcfg ReadFileMod model &lt;id&gt;</code>"
            )
            return

        await self._ui.show_models(self, call, models, 0, pid)

    async def _models_page_cb(self, call: InlineCall, page: int, pid: str):
        models = await self._get_models(pid)
        if not models:
            models = [{"id": "? No models available", "label": "N/A", "ctx": "0"}]
        await self._ui.show_models(self, call, models, page, pid)

    async def _back_providers_cb(self, call: InlineCall):
        await self._ui.show_providers(self, call)

    async def _settings_models_cb(self, call: InlineCall):
        pid = self._providers.active
        models = await self._get_models(pid)
        if not models:
            prov_info = self._providers.info(pid)
            await call.edit(
                f"<b>{prov_info['label']}</b>\n\nНе удалось получить список моделей.\n"
                f"Проверьте API ключ или установите модель вручную: <code>.fcfg ReadFileMod model &lt;id&gt;</code>",
                reply_markup=[[{"text": "← Настройки", "callback": self._show_settings}]],
            )
            return
        await self._ui.show_models(self, call, models, 0, pid)

    async def _settings_scan_cb(self, call: InlineCall):
        await call.edit("Сканирую KeyScanner...")
        await self._scan_keyscanner()
        await self._show_settings(call)

    async def _clean_cache_cb(self, call: InlineCall):
        removed = self._cache.clear()
        for uid in list(self._user_data):
            self._clean_udata(uid)
        await call.edit(
            f"<b>Кеш очищен</b>\n"
            f"Удалено файлов: {removed}"
        )

    async def _update_cb(self, call: InlineCall, content: str):
        match = re.search(r"__version__\s*=\s*\((\d+),\s*(\d+),\s*(\d+)\)", content)
        ver = ".".join(match.groups()) if match else "?"
        try:
            await call.edit("Обновление...")
            loader_mod = self.lookup("loader")
            if not loader_mod:
                await call.edit("Не найден loader")
                return
            url = "https://raw.githubusercontent.com/Holy16rus/Module-Holy/main/ReadFileMod.py"
            await loader_mod.download_and_install(url, None)
            await call.edit(f"Модуль обновлен до {ver}. Перезагрузите: .restart")
        except Exception as e:
            await call.edit(f"Ошибка: {e}")

    async def on_unload(self):
        await self._ai.close()
        for uid in list(self._user_data):
            self._clean_udata(uid)


def _ufmt(s: str) -> str:
    """Clean up error messages: remove redundant prefixes."""
    s = re.sub(r"^ConnectionError:\s*", "", s)
    s = re.sub(r"^Exception:\s*", "", s)
    return s.strip()
