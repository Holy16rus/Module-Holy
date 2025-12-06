# 🌐 https://github.com/Holy16rus/Module-Holy/blob/main/ReadFileMod.py
# meta developer: @CoderHoly


import os
import json
import httpx
import re
import base64
import zlib
import logging
import hashlib
import tempfile
from telethon.tl.types import Message
from .. import loader, utils

logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
__version__ = (1, 6, 7)

@loader.tds
class ReadFileMod(loader.Module):
    strings = {"name": "ReadFileMod"}

    def __init__(self):
        self.chunks = []
        self.file_info = {}
        self.file_content = ""
        self.file_path = ""
        self._desc_cache: dict[str, str] = {}
        self._analyzed_count = 0

        self._async_cmd_re = re.compile(r'async\s+def\s+(\w+cmd)\s*\(')
        self._sync_cmd_re = re.compile(r'def\s+(\w+cmd)\s*\(')

        self._loader_cmd_re = re.compile(
            r'@loader\.command\s*\((?:[^)]*?ru_doc\s*=\s*["\']([^"\']+)["\'])?[^)]*?\)\s*async\s+def\s+(\w+)\s*\(',
            re.DOTALL | re.IGNORECASE
        )

        self._class_name_re = re.compile(
            r'class\s+(\w+)\s*\(\s*(?:loader\.)?Module\s*\)', re.IGNORECASE
        )

        self._strings_name_re = re.compile(
            r'strings\s*=\s*\{.*?["\']name["\']\s*:\s*["\']([^"\']+)["\']',
            re.DOTALL | re.IGNORECASE
        )

        self._b64_zlib_re = re.compile(r"b'([A-Za-z0-9+/=]+)'")

        raw_patterns = [
            (r"DeleteAccountRequest", "Попытка удаления аккаунта", "critical"),
            (r"ResetAuthorizationRequest", "Сброс всех сеансов авторизации", "critical"),
            (r"export_session_string", "Экспорт сессии (угон аккаунта)", "critical"),
            (r"edit_2fa|edit_cloud_password", "Смена пароля 2FA", "critical"),
            (r"terminate_all_sessions", "Завершение всех сеансов", "critical"),
            (r"\.session", "Работа с .session файлом", "critical"),
            (r"os\.environ", "Чтение переменных окружения", "warning"),
            (r"config\.env", "Чтение config.env", "warning"),
            (r"os\.system", "Выполнение системных команд", "critical"),
            (r"subprocess\.Popen|subprocess\.call", "Запуск внешних процессов", "critical"),
            (r"socket\.socket", "Создание сокетов", "critical"),
            (r"shutil\.rmtree", "Рекурсивное удаление файлов", "warning"),
            (r"(requests|httpx|aiohttp)\.post", "Отправка данных POST-запросами", "warning"),
            (r"GetHistoryRequest|GetMessagesRequest", "Массовое чтение переписок", "warning"),
            (r"ctypes\.CDLL", "Загрузка нативных библиотек", "critical"),
        ]
        self._patterns = [
            (re.compile(p, re.IGNORECASE), msg, sev) for p, msg, sev in raw_patterns
        ]

        self._ignored_cmds = {"myname", "cmd", "func", "wrapper", "main"}
        self._http_client: httpx.AsyncClient | None = None

        self._cache_dir = os.path.join(tempfile.gettempdir(), "readfilemod_cache")
        os.makedirs(self._cache_dir, exist_ok=True)

        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "provider",
                "OpenRouter",
                "Провайдер AI (по умолчанию OpenRouter)",
                validator=loader.validators.Choice(["OpenRouter"]),
            ),
            loader.ConfigValue(
                "model",
                "kwaipilot/kat-coder-pro:free",
                "Модель ИИ для анализа кода",
            ),
            loader.ConfigValue(
                "api_key",
                None,
                "API ключ OpenRouter",
                validator=loader.validators.Hidden(),
            ),
            loader.ConfigValue(
                "proxy",
                "",
                "Прокси (http://user:pass@host:port)",
                validator=loader.validators.String(),
            ),
        )

    def _content_hash(self, content: str) -> str:
        h = hashlib.sha256()
        h.update(content.encode("utf-8"))
        return h.hexdigest()

    def _cache_path_for_hash(self, h: str) -> str:
        return os.path.join(self._cache_dir, f"{h}.json")

    def _load_ai_cache(self, h: str) -> str | None:
        path = self._cache_path_for_hash(h)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data.get("ai_raw_json")
            except Exception:
                return None
        return None

    def _save_ai_cache(self, h: str, ai_raw_json: str):
        path = self._cache_path_for_hash(h)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"ai_raw_json": ai_raw_json}, f, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"Не удалось сохранить кеш: {e}")

    async def _get_http_client(self):
        if self._http_client is None:
            proxy = self.config.get("proxy") or None
            client_args = {"timeout": 60}
            if proxy:
                client_args["proxies"] = proxy
            self._http_client = httpx.AsyncClient(**client_args)
        return self._http_client

    def _decode_base64_zlib(self, encoded_string: str) -> str:
        try:
            decoded_bytes = base64.b64decode(encoded_string)
            decompressed_bytes = zlib.decompress(decoded_bytes)
            return decompressed_bytes.decode("utf-8")
        except Exception as e:
            logger.debug(f"Ошибка при декодировании base64+zlib: {e}")
            raise ValueError("Incorrect padding")

    def _try_decode(self, code: str) -> tuple[str, bool]:
        if "__import__('zlib')" in code and "__import__('base64')" in code:
            match = self._b64_zlib_re.search(code)
            if match:
                try:
                    encoded_string = match.group(1)
                    decoded_code = self._decode_base64_zlib(encoded_string)
                    logger.info("Код успешно декодирован.")
                    return decoded_code, True
                except Exception:
                    logger.debug("Не удалось декодировать код — пропускаем.")
                    return code, False
        return code, False

    def _recursive_decode(self, content: str, depth: int = 0) -> str:
        if depth > 5:
            return content
        try:
            m = self._b64_zlib_re.search(content)
            if m:
                encoded_string = m.group(1)
                try:
                    decoded_bytes = base64.b64decode(encoded_string)
                    try:
                        res = zlib.decompress(decoded_bytes).decode("utf-8")
                    except zlib.error:
                        res = decoded_bytes.decode("utf-8", errors="ignore")
                    return self._recursive_decode(res, depth + 1)
                except Exception:
                    return content
            if len(content) > 100 and " " not in content[:50]:
                try:
                    res = base64.b64decode(content).decode("utf-8")
                    return self._recursive_decode(res, depth + 1)
                except Exception:
                    pass
        except Exception:
            pass
        return content

    async def _generate_description(self, content: str, json_mode: bool = True) -> str:
        model = self.config["model"]
        api_key = self.config["api_key"]
        if not api_key:
            return "❌ Ошибка: Не указан API ключ OpenRouter."

        if json_mode:
            system_prompt = (
                "Ты — эксперт по кибербезопасности и анализу Python-кода для Telegram-юзерботов "
                "(Hikka, Heroku, Telethon). "
                "Твоя задача — проанализировать код модуля и оценить его с точки зрения безопасности. "
                "Верни ТОЛЬКО JSON строго в формате:\n"
                "{\n"
                '  \"статус\": \"Безопасный модуль ✅\" ИЛИ \"Установка на ваш риск 👀\" ИЛИ \"Опасный модуль 📛\",\n'
                '  \"назначение\": \"Краткое описание назначения модуля\",\n'
                '  \"возможности\": [\"Функция 1\", \"Функция 2\"],\n'
                '  \"опасности\": [\"Опасное действие 1\", \"Опасное действие 2\"]\n'
                "}\n"
                "Интерпретация статусов:\n"
                "• \"Опасный модуль 📛\" — только если модуль явно направлен на кражу аккаунта, кражу сессии, удаление аккаунта, "
                "массовую утечку данных, скрытый контроль владельца, выполнение произвольного кода или похожие критические действия.\n"
                "• \"Установка на ваш риск 👀\" — если модуль сам по себе не крадёт аккаунт и не наносит прямой вред владельцу, "
                "но может привести к блокировке, нарушает правила сервисов, агрессивно спамит, автоматизирует войны/рейды/игровые боты "
                "или может использоваться во вред другим пользователям.\n"
                "• \"Безопасный модуль ✅\" — если модуль выполняет полезные или нейтральные функции и не содержит опасных действий.\n"
                "Поле \"опасности\" обязательно (может быть пустым массивом []). Там перечисляй конкретные риски и возможные "
                "последствия для владельца аккаунта и других пользователей. Не добавляй никакого текста вокруг JSON."
            )
        else:
            system_prompt = (
                "Ты — помощник по описанию команд в Python-коде. "
                "Отвечай очень кратко, по-русски, без лишнего текста."
            )

        safe_content = content[:40000]
        user_content = f"Код для анализа:\n\n```python\n{safe_content}\n```"

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        }

        try:
            client = await self._get_http_client()
            response = await client.post(
                OPENROUTER_API_URL,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.debug(f"API error: {e}")
            return f"❌ Ошибка API: {e}"

    async def _describe_command(self, cmd: str, code: str) -> str:
        if cmd in self._desc_cache:
            return self._desc_cache[cmd]
        prompt = (
            f"Кратко и по-русски опиши, что делает команда «{cmd}» в этом коде. "
            f"Не более 10 слов. Только суть."
        )
        try:
            response = await self._generate_description(
                prompt + "\n\n" + code, json_mode=False
            )
            if not response.startswith("❌"):
                res = response.strip('." \n`')
                self._desc_cache[cmd] = res
                return res
        except Exception:
            pass
        return "выполняет команду"

    def _analyze_file_for_safety(self, content: str) -> tuple:
        decoded_content, is_decoded = self._try_decode(content)
        if not is_decoded:
            decoded_content = self._recursive_decode(content)
            is_decoded = decoded_content != content

        critical = []
        warnings = []
        suspicious = []

        if is_decoded:
            suspicious.append("Код был деобфусцирован (распакован) для анализа")

        for cre, msg, sev in self._patterns:
            if cre.search(decoded_content):
                if sev == "critical":
                    critical.append(msg)
                else:
                    warnings.append(msg)

        if "eval(" in decoded_content or "exec(" in decoded_content:
            suspicious.append("Использование eval/exec (динамическое исполнение кода)")

        if "meta developer:" not in decoded_content:
            suspicious.append("Отсутствует meta developer (автор модуля не указан)")

        if "api_id" in decoded_content and "api_hash" in decoded_content:
            suspicious.append("Обнаружены api_id/api_hash в коде")

        return critical, warnings, suspicious, decoded_content

    def _format_size(self, size: int) -> str:
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} мб"
        elif size >= 1024:
            return f"{int(size / 1024)} кб"
        else:
            return f"{size} байт"

    def _get_cache_stats(self) -> tuple[int, int]:
        total_bytes = 0
        total_files = 0

        if os.path.isdir(self._cache_dir):
            for root, dirs, files in os.walk(self._cache_dir):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        total_bytes += os.path.getsize(path)
                        total_files += 1
                    except OSError:
                        pass

        if self.file_path and os.path.exists(self.file_path):
            try:
                total_bytes += os.path.getsize(self.file_path)
                total_files += 1
            except OSError:
                pass

        return total_bytes, total_files

    async def rfcmd(self, message: Message):
        """.rf <reply to file> — анализ и чтение файла"""
        reply = await message.get_reply_message()
        if not reply or not reply.file:
            await message.edit("❌ Ответьте на файл.")
            return

        if self.file_path and os.path.exists(self.file_path):
            try:
                os.remove(self.file_path)
            except Exception:
                pass

        await message.edit(f"⏳ Чтение файла: {reply.file.name}...")
        self.file_path = await reply.download_media()
        self.chunks = []
        self.file_content = ""
        self.file_info = {}

        try:
            if os.path.getsize(self.file_path) > 10 * 1024 * 1024:
                await message.edit("❌ Файл слишком большой.")
                return
            with open(self.file_path, "r", encoding="utf-8") as f:
                self.file_content = f.read()
        except Exception as e:
            await message.edit(f"❌ Ошибка чтения: {e}")
            return

        self.chunks = self._split_text(self.file_content, 1500)
        self.file_info = {
            "Имя": os.path.basename(self.file_path),
            "Размер": os.path.getsize(self.file_path),
            "Страниц": len(self.chunks),
            "Путь": self.file_path,
        }
        self._analyzed_count += 1
        await self._show_page(message, 0)

    def _split_text(self, text, size):
        return [text[i: i + size] for i in range(0, len(text), size)]

    async def _show_page(self, msg_or_call, index):
        if not self.chunks:
            text = "❌ Файл пуст."
            buttons = [[{"text": "↩️ Закрыть", "action": "close"}]]
            if isinstance(msg_or_call, Message):
                await self.inline.form(
                    text=text, message=msg_or_call, reply_markup=buttons
                )
            elif hasattr(msg_or_call, "edit"):
                await msg_or_call.edit(text=text, reply_markup=buttons)
            return

        total = len(self.chunks)
        index = max(0, min(index, total - 1))
        text = (
            f"📒 Страница {index + 1}/{total}\n"
            f"<pre>{utils.escape_html(self.chunks[index])}</pre>"
        )
        buttons = [
            [
                {
                    "text": "⬅️",
                    "callback": self._page_cb,
                    "args": (index - 1,),
                },
                {
                    "text": "➡️",
                    "callback": self._page_cb,
                    "args": (index + 1,),
                },
            ],
            [{"text": "🕵️ Анализ", "callback": self._info_cb, "args": (index,)}],
        ]
        if isinstance(msg_or_call, Message):
            await self.inline.form(
                text=text,
                message=msg_or_call,
                reply_markup=buttons
            )
        elif hasattr(msg_or_call, "edit"):
            await msg_or_call.edit(text=text, reply_markup=buttons)

    async def _page_cb(self, call, index):
        await self._show_page(call, index)

    async def _info_cb(self, call, return_index):
        await call.answer("⏳ Углубленный анализ...", show_alert=False)

        display_name = "N/A"
        filename = self.file_info.get("Имя", "N/A")

        class_match = self._class_name_re.search(self.file_content)
        if class_match:
            display_name = class_match.group(1)
        else:
            strings_match = self._strings_name_re.search(self.file_content)
            if strings_match:
                display_name = strings_match.group(1)
            else:
                clean_name = re.sub(r"\s*\(\d+\)", "", filename)
                display_name = clean_name
                if display_name.endswith(".py"):
                    display_name = display_name[:-3]

        fsize = int(self.file_info.get("Размер", 0))
        pages = self.file_info.get("Страниц", 0)
        size_str = self._format_size(fsize)

        crit_list, warn_list, susp_list, working_content = (
            self._analyze_file_for_safety(self.file_content)
        )

        content_hash = self._content_hash(working_content)
        ai_raw_json = self._load_ai_cache(content_hash)
        if ai_raw_json is None:
            ai_raw_json = await self._generate_description(
                working_content, json_mode=True
            )
            if not ai_raw_json.startswith("❌"):
                try:
                    cleaned = re.sub(
                        r"```json\n|```json|```|\n", "", ai_raw_json
                    ).strip()
                    json.loads(cleaned)
                    self._save_ai_cache(content_hash, ai_raw_json)
                except Exception:
                    pass

        ai_data = {
            "статус": "Установка на ваш риск 👀",
            "назначение": "Не удалось проанализировать",
            "возможности": [],
            "опасности": [],
        }
        if ai_raw_json and not ai_raw_json.startswith("❌"):
            try:
                cleaned = re.sub(
                    r"```json\n|```json|```|\n", "", ai_raw_json
                ).strip()
                loaded = json.loads(cleaned)
                ai_data.update(loaded)
            except Exception:
                pass

        status = utils.escape_html(ai_data.get("статус", "Установка на ваш риск 👀"))
        purpose = utils.escape_html(ai_data.get("назначение", "Нет описания"))
        general_caps = ai_data.get("возможности", []) or []
        ai_risks = ai_data.get("опасности", []) or []

        command_lines = []
        found_cmd_names = set()

        loader_matches = self._loader_cmd_re.findall(working_content)
        has_loader_cmds = bool(loader_matches)

        for doc_text, cmd_name in loader_matches:
            if cmd_name in self._ignored_cmds:
                continue
            found_cmd_names.add(cmd_name)
            if doc_text:
                desc = doc_text.replace("\n", " ").strip()
            else:
                desc = await self._describe_command(cmd_name, working_content)
            formatted_cmd = (
                f"Команда «{utils.escape_html(cmd_name)}» | {utils.escape_html(desc)}"
            )
            command_lines.append(formatted_cmd)

        if not has_loader_cmds:
            classic_cmds = self._async_cmd_re.findall(working_content)
            if not classic_cmds:
                classic_cmds = self._sync_cmd_re.findall(working_content)
        else:
            classic_cmds = []

        clean_classic_cmds = []
        for name in classic_cmds:
            base = name[:-3] if name.endswith("cmd") else name
            clean_classic_cmds.append(base)

        for cmd in clean_classic_cmds:
            if cmd in found_cmd_names or cmd in self._ignored_cmds:
                continue
            desc = await self._describe_command(cmd, working_content)
            formatted_cmd = (
                f"Команда «{utils.escape_html(cmd)}» | {utils.escape_html(desc)}"
            )
            command_lines.append(formatted_cmd)

        text = (
            "📄 <b>Информация о модуле</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"<b>Имя:</b> {utils.escape_html(display_name)}\n"
            f"<b>Размер:</b> {size_str}\n"
            f"<b>Страниц:</b> {pages}\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"🤖 <b>AI-Анализ | {status}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
        )

        text += "🔹<b>Назначение модуля:</b>\n"
        text += f"<blockquote>{purpose}</blockquote>\n"

        if general_caps or command_lines:
            text += "⚙️<b> Возможности и Команды:</b>\n"
            combined_list = [f"• {c}" for c in command_lines]
            combined_list.extend(
                [f"• {utils.escape_html(c)}" for c in general_caps]
            )
            cmds_str = "\n".join(combined_list)
            text += f"<blockquote>{cmds_str}</blockquote>\n"

        if ai_risks:
            dangers_str = "\n".join([f"• {utils.escape_html(d)}" for d in ai_risks])
            text += "☢️ <b>Опасные или рискованные действия:</b>\n"
            text += f"<blockquote>{dangers_str}</blockquote>\n"

        all_heur = crit_list + warn_list + susp_list
        if all_heur:
            heur_str = "\n".join([f"• {utils.escape_html(d)}" for d in all_heur])
            text += "🧪 <b>Статический анализ (эвристика):</b>\n"
            text += f"<blockquote>{heur_str}</blockquote>"

        await call.edit(
            text=text,
            reply_markup=[
                [
                    {
                        "text": "↩️ Назад к коду",
                        "callback": self._page_cb,
                        "args": (return_index,),
                    }
                ]
            ],
        )

    async def cccmd(self, message: Message):
        """Показать статистику кеша и очистить при необходимости (.cc)"""
        total_bytes, total_files = self._get_cache_stats()
        size_str = self._format_size(total_bytes)

        text = (
            "📊 <b>Статистика кеша ReadFileMod</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"<b>Занятое место временной папки:</b> {size_str}\n"
            f"<b>Файлов во временной папке:</b> {total_files}\n"
            f"<b>Проанализированных модулей:</b> {self._analyzed_count}\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Нажми кнопку ниже, чтобы очистить кеш и временные файлы."
        )

        await self.inline.form(
            text=text,
            message=message,
            reply_markup=[
                [{"text": "Очистить 🚮", "callback": self._clear_cache_cb}]
            ],
        )

    async def _clear_cache_cb(self, call):
        removed_files = 0
        removed_cache = 0

        if self.file_path and os.path.exists(self.file_path):
            try:
                os.remove(self.file_path)
                removed_files += 1
            except Exception:
                pass

        self.file_path = ""
        self.chunks = []

        if os.path.isdir(self._cache_dir):
            for filename in os.listdir(self._cache_dir):
                path = os.path.join(self._cache_dir, filename)
                try:
                    os.remove(path)
                    removed_cache += 1
                except Exception:
                    pass

        self._desc_cache.clear()
        self._analyzed_count = 0

        await call.edit(
            "🧹 <b>Кеш и временные файлы очищены!</b>\n"
            f"• Удалено временных файлов: {removed_files}\n"
            f"• Удалено файлов кеша: {removed_cache}\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Можно продолжать анализ новых модулей 🙂"
        )

    async def on_unload(self):
        if self.file_path and os.path.exists(self.file_path):
            try:
                os.remove(self.file_path)
            except Exception:
                pass
        if self._http_client:
            try:
                await self._http_client.aclose()
            except Exception:
                pass