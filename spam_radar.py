"""Spam Radar — on-device heuristic spam scoring for exteraGram.

No network calls, no ML, no data leaves the device. Every score is the sum of
transparent signals (Telegram's own scam/fake flags, profile completeness,
message text, links, formatting), so you can always see *why* a chat scored.
"""

import re
import time

from android_utils import run_on_ui_thread
from base_plugin import BasePlugin, HookResult, MenuItemData, MenuItemType
from client_utils import (
    PLUGINS_QUEUE,
    get_contacts_controller,
    get_last_fragment,
    get_messages_controller,
    get_selected_account,
    get_user_config,
    run_on_queue,
)
from ui.bulletin import BulletinHelper
from ui.settings import Divider, Header, Input, Selector, Switch, Text

__id__ = "spam_radar"
__name__ = "Spam Radar"
__description__ = "Scores chats and incoming messages with on-device heuristics and warns you about likely spam. Nothing is sent anywhere."
__author__ = "Your Name"
__version__ = "1.0.0"
__icon__ = "exteraPlugins/1"
__app_version__ = ">=12.5.1"
__sdk_version__ = ">=1.4.5.0"
__requirements__ = []
__category__ = ["tools", "privacy"]


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Selector index -> minimum score that triggers a warning.
# Index 0 = "Low" sensitivity (only very obvious spam), 2 = "High" (catches more).
SENSITIVITY_THRESHOLDS = (75, 60, 45)

MAX_SCAN_DIALOGS = 250
MAX_SAMPLE_MESSAGES = 5
RECENT_WARNING_WINDOW = 600  # seconds

STRONG_PHRASES = (
    "guaranteed profit",
    "guaranteed income",
    "risk-free profit",
    "risk free profit",
    "double your",
    "free crypto",
    "free bitcoin",
    "crypto giveaway",
    "airdrop",
    "dm me",
    "join my channel",
    "join my group",
    "subscribe to my channel",
    "click the link",
    "work from home",
    "passive income",
    "onlyfans",
    "casino",
    "1xbet",
    "investment plan",
    "signal group",
    "pump and dump",
    "presale",
    "whitelist spot",
)

WEAK_TERMS = (
    "crypto",
    "bitcoin",
    "usdt",
    "forex",
    "profit",
    "invest",
    "betting",
    "loan",
)

NAME_FLAGS = (
    "crypto",
    "investment",
    "profit",
    "giveaway",
    "casino",
    "airdrop",
    "forex",
    "signals",
    "earn money",
    "betting",
    "loan",
)

LINK_RE = re.compile(r"(https?://|www\.|t\.me/)", re.IGNORECASE)
INVITE_RE = re.compile(r"(t\.me/\+|joinchat/)", re.IGNORECASE)
MONEY_RE = re.compile(r"[$€£₹₽]\s?\d")
REPEAT_RE = re.compile(r"(.)\1{4,}")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _username(entity):
    value = getattr(entity, "username", None)
    return str(value) if value else ""


def _has_photo(entity):
    photo = getattr(entity, "photo", None)
    if photo is None:
        return False
    return getattr(photo, "photo_small", None) is not None


def _display_name(entity):
    title = getattr(entity, "title", None)
    if title:
        return str(title)
    first = getattr(entity, "first_name", None) or ""
    last = getattr(entity, "last_name", None) or ""
    name = f"{first} {last}".strip()
    if name:
        return name
    username = _username(entity)
    return f"@{username}" if username else "Unknown chat"


def _emoji_ratio(text):
    if not text:
        return 0.0
    count = 0
    for char in text:
        code = ord(char)
        if 0x1F300 <= code <= 0x1FAFF or 0x2600 <= code <= 0x27BF:
            count += 1
    return count / len(text)


def verdict_for(score):
    if score >= 70:
        return "likely spam"
    if score >= 40:
        return "suspicious"
    return "looks clean"


def score_chat(entity, text, extra_keywords=(), forwarded=False):
    """Return (score 0..100, list of human-readable reasons)."""
    score = 0
    reasons = []

    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    is_chat = hasattr(entity, "title")

    # Telegram's own moderation flags are the strongest signal.
    if bool(getattr(entity, "scam", False)):
        add(55, "flagged as scam by Telegram")
    if bool(getattr(entity, "fake", False)):
        add(45, "flagged as fake by Telegram")
    if bool(getattr(entity, "restricted", False)):
        add(10, "restricted account")

    # Trust signals subtract.
    if bool(getattr(entity, "verified", False)):
        score -= 25
    if not is_chat and bool(getattr(entity, "premium", False)):
        score -= 8

    # Profile completeness.
    if not _username(entity):
        add(5 if is_chat else 8, "no username")
    if not _has_photo(entity):
        add(8 if is_chat else 10, "no profile photo")

    if is_chat:
        participants = int(getattr(entity, "participants_count", 0) or 0)
        if 0 < participants < 10:
            add(8, f"only {participants} member(s)")

    # Suspicious name.
    lowered_name = _display_name(entity).lower()
    for word in NAME_FLAGS:
        if word in lowered_name:
            add(10, f'name contains "{word}"')
            break

    # Message content.
    lowered = (text or "").lower()
    if lowered:
        strong_hits = [word for word in STRONG_PHRASES if word in lowered]
        if strong_hits:
            add(min(42, 14 * len(strong_hits)), "spam phrases: " + ", ".join(strong_hits[:3]))

        weak_hits = [word for word in WEAK_TERMS if word in lowered]
        if weak_hits:
            add(min(15, 5 * len(weak_hits)), "risky words: " + ", ".join(weak_hits[:3]))

        extra_hits = [word for word in extra_keywords if word and word in lowered]
        if extra_hits:
            add(min(30, 10 * len(extra_hits)), "your keywords: " + ", ".join(extra_hits[:3]))

        links = len(LINK_RE.findall(text))
        if links:
            add(8 if links < 3 else 18, f"{links} link(s) in the message")
        if INVITE_RE.search(text):
            add(12, "private invite link")
        if MONEY_RE.search(text):
            add(6, "money amounts")

        letters = [char for char in text if char.isalpha()]
        if len(letters) >= 12:
            uppercase = sum(1 for char in letters if char.isupper())
            if uppercase / len(letters) > 0.5:
                add(10, "mostly capital letters")

        if len(text) > 10 and _emoji_ratio(text) > 0.15:
            add(8, "emoji overload")

        if REPEAT_RE.search(text):
            add(5, "repeated characters")

    if forwarded:
        add(6, "forwarded message")

    return max(0, min(100, score)), reasons


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class SpamRadarPlugin(BasePlugin):
    def on_plugin_load(self):
        self._recent = {}

        # New private/group messages and new channel/supergroup messages.
        self.add_hook("TL_updateNewMessage")
        self.add_hook("TL_updateNewChannelMessage")

        self._scan_item = self.add_menu_item(
            MenuItemData(
                menu_type=MenuItemType.DRAWER_MENU,
                text="Scan chats for spam",
                on_click=self._on_scan_menu,
                icon="msg_search",
                subtext="Spam Radar",
                priority=10,
            )
        )
        self._message_item = self.add_menu_item(
            MenuItemData(
                menu_type=MenuItemType.MESSAGE_CONTEXT_MENU,
                text="Check for spam",
                on_click=self._on_check_message,
                icon="msg_info",
                priority=10,
            )
        )
        self.logger.info("Spam Radar loaded")

    def on_plugin_unload(self):
        # Menu items and hooks are detached by the SDK automatically; the cache
        # is the only state we own.
        self._recent = {}

    # -- incoming messages --------------------------------------------------

    def on_update_hook(self, update_name, account, update):
        if update_name not in ("TL_updateNewMessage", "TL_updateNewChannelMessage"):
            return HookResult()

        data = self._read_update(update)
        if data is None:
            return HookResult()

        # Keep the hook itself trivial; analysis runs on the plugins queue.
        run_on_queue(lambda: self._auto_check(account, data), PLUGINS_QUEUE)
        return HookResult()

    def _read_update(self, update):
        try:
            raw = getattr(update, "message", None)
            if raw is None:
                return None

            owner = getattr(raw, "messageOwner", None)
            if owner is None:
                owner = raw

            outgoing = bool(getattr(owner, "out", False))
            if not outgoing and hasattr(raw, "isOut"):
                outgoing = bool(raw.isOut())
            if outgoing:
                return None

            dialog_id = self._dialog_id(owner)
            if not dialog_id:
                return None

            return {
                "dialog_id": int(dialog_id),
                "sender_id": self._peer_dialog_id(getattr(owner, "from_id", None)),
                "text": self._text_of(raw, owner),
                "forwarded": getattr(owner, "fwd_from", None) is not None,
            }
        except Exception:
            self.logger.exception("Could not read update")
            return None

    def _auto_check(self, account, data):
        try:
            if not bool(self.get_setting("auto_check", True)):
                return

            dialog_id = data["dialog_id"]
            controller = get_messages_controller(account)
            chat = controller.getUserOrChat(dialog_id)
            if chat is None or self._is_self(account, dialog_id):
                return

            target = self._pick_target(account, controller, chat, data.get("sender_id", 0))

            if bool(self.get_setting("ignore_contacts", True)) and self._is_contact(account, target):
                return

            score, reasons = score_chat(
                target,
                data["text"],
                self._extra_keywords(),
                data["forwarded"],
            )
            if score < self._threshold():
                return
            if self._recently_warned(account, dialog_id):
                return

            name = _display_name(target)
            detail = ", ".join(reasons[:3]) if reasons else "no strong signals"
            BulletinHelper.show_info(f"Possible spam from {name} ({score}%): {detail}")
            self.logger.info(f"[account {account}] {name} scored {score}: {detail}")
        except Exception:
            self.logger.exception("Auto check failed")

    # -- manual checks ------------------------------------------------------

    def _on_scan_menu(self, *args):
        self._start_scan()

    def _on_scan_click(self, *args):
        self._start_scan()

    def _start_scan(self):
        try:
            account = get_selected_account()
        except Exception:
            BulletinHelper.show_error("No active account.")
            return
        BulletinHelper.show_info("Scanning chats…")
        run_on_queue(lambda: self._scan(account), PLUGINS_QUEUE)

    def _scan(self, account):
        try:
            controller = get_messages_controller(account)
            threshold = self._threshold()
            extra = self._extra_keywords()
            ignore_contacts = bool(self.get_setting("ignore_contacts", True))

            hits = []
            scanned = 0
            seen = set()

            for folder in (0, 1):  # main list + archived
                if scanned >= MAX_SCAN_DIALOGS:
                    break
                dialogs = controller.getDialogs(folder) or []
                try:
                    dialogs = list(dialogs)
                except Exception:
                    dialogs = []
                for dialog in dialogs:
                    if scanned >= MAX_SCAN_DIALOGS:
                        break
                    dialog_id = int(dialog.id)
                    if not dialog_id or dialog_id in seen:
                        continue
                    seen.add(dialog_id)

                    entity = controller.getUserOrChat(dialog_id)
                    if entity is None or self._is_self(account, dialog_id):
                        continue
                    if ignore_contacts and self._is_contact(account, entity):
                        continue
                    # Legitimate bots are noisy to score; only keep flagged ones.
                    if bool(getattr(entity, "bot", False)) and not (
                        bool(getattr(entity, "scam", False))
                        or bool(getattr(entity, "fake", False))
                    ):
                        continue

                    scanned += 1
                    text, forwarded = self._chat_sample(controller, dialog_id)
                    score, reasons = score_chat(entity, text, extra, forwarded)
                    if score >= threshold:
                        hits.append((score, _display_name(entity), reasons))

            hits.sort(key=lambda item: item[0], reverse=True)
            message = self._format_scan(hits, scanned, threshold)
            run_on_ui_thread(lambda: self._present("Spam scan", message))
        except Exception:
            self.logger.exception("Scan failed")
            run_on_ui_thread(
                lambda: self._present(
                    "Spam scan",
                    "The scan failed. Check the plugin log for details.",
                )
            )

    def _on_check_message(self, context=None):
        if not isinstance(context, dict):
            context = {}
        raw_account = context.get("account")
        try:
            account = int(raw_account) if raw_account is not None else get_selected_account()
        except (TypeError, ValueError):
            account = get_selected_account()

        dialog_id = 0
        try:
            dialog_id = int(context.get("dialog_id") or 0)
        except (TypeError, ValueError):
            dialog_id = 0

        text = ""
        forwarded = False
        sender_id = 0
        message = context.get("message")
        if message is not None:
            owner = getattr(message, "messageOwner", None)
            if owner is None:
                owner = message
            if not dialog_id:
                dialog_id = self._dialog_id(owner)
            text = self._text_of(message, owner)
            forwarded = getattr(owner, "fwd_from", None) is not None
            sender_id = self._peer_dialog_id(getattr(owner, "from_id", None))

        if not dialog_id:
            BulletinHelper.show_error("Could not determine the chat.")
            return

        run_on_queue(
            lambda: self._check_now(account, dialog_id, text, forwarded, sender_id),
            PLUGINS_QUEUE,
        )

    def _check_now(self, account, dialog_id, text, forwarded, sender_id=0):
        try:
            controller = get_messages_controller(account)
            chat = controller.getUserOrChat(dialog_id)
            if chat is None:
                run_on_ui_thread(
                    lambda: BulletinHelper.show_error("Chat data is not available yet.")
                )
                return

            target = self._pick_target(account, controller, chat, sender_id)
            score, reasons = score_chat(
                target,
                text,
                self._extra_keywords(),
                forwarded,
            )
            name = _display_name(target)
            lines = [f"{name}: {score}% — {verdict_for(score)}.", ""]
            if reasons:
                lines.extend(f"• {reason}" for reason in reasons)
            else:
                lines.append("No spam signals were found.")
            lines.extend(["", "Heuristic result, not proof."])

            message = "\n".join(lines)
            run_on_ui_thread(lambda: self._present("Spam check", message))
        except Exception:
            self.logger.exception("Check failed")

    # -- presentation -------------------------------------------------------

    def _present(self, title, message):
        """Show a result dialog. Must be called on the UI thread."""
        try:
            from ui.alert import AlertDialogBuilder
        except Exception:
            BulletinHelper.show_info(f"{title}: {message[:300]}")
            return

        try:
            fragment = get_last_fragment()
            activity = fragment.getParentActivity() if fragment is not None else None
            if activity is None:
                BulletinHelper.show_info(f"{title}: {message[:300]}")
                return

            builder = AlertDialogBuilder(activity)
            builder.set_title(title)
            builder.set_message(message)
            builder.set_positive_button("OK", lambda bld, which: bld.dismiss())
            builder.create()
            builder.show()
        except Exception:
            self.logger.exception("Could not show dialog")
            try:
                BulletinHelper.show_info(f"{title}: {message[:300]}")
            except Exception:
                pass

    @staticmethod
    def _format_scan(hits, scanned, threshold):
        if not hits:
            return f"Checked {scanned} chat(s). Nothing above the {threshold}% threshold."

        lines = [f"Checked {scanned} chat(s). Suspicious:", ""]
        for score, name, reasons in hits[:10]:
            detail = ", ".join(reasons[:3]) if reasons else "no strong signals"
            lines.append(f"{score}% — {name}")
            lines.append(f"   {detail}")
        if len(hits) > 10:
            lines.extend(["", f"…and {len(hits) - 10} more."])
        lines.extend(["", "Heuristic result, not proof. Verify before acting."])
        return "\n".join(lines)

    # -- data helpers -------------------------------------------------------

    @staticmethod
    def _text_of(raw, owner):
        value = getattr(owner, "message", None)
        if isinstance(value, str):
            return value[:2000]
        value = getattr(raw, "messageText", None)
        if value is not None:
            return str(value)[:2000]
        return ""

    @staticmethod
    def _peer_dialog_id(peer):
        if peer is None:
            return 0
        user_id = int(getattr(peer, "user_id", 0) or 0)
        chat_id = int(getattr(peer, "chat_id", 0) or 0)
        channel_id = int(getattr(peer, "channel_id", 0) or 0)
        if user_id:
            return user_id
        if chat_id:
            return -chat_id
        if channel_id:
            return -channel_id
        return 0

    @staticmethod
    def _dialog_id(owner):
        dialog_id = SpamRadarPlugin._peer_dialog_id(getattr(owner, "peer_id", None))
        if dialog_id:
            return dialog_id

        dialog_id = getattr(owner, "dialog_id", None)
        if dialog_id is not None:
            try:
                return int(dialog_id)
            except (TypeError, ValueError):
                return 0
        return 0

    @staticmethod
    def _chat_sample(controller, dialog_id):
        parts = []
        forwarded = False
        try:
            messages = controller.dialogMessage.get(dialog_id)
            if messages:
                for message in list(messages)[:MAX_SAMPLE_MESSAGES]:
                    text = getattr(message, "messageText", None)
                    if text:
                        parts.append(str(text)[:400])
                    owner = getattr(message, "messageOwner", None)
                    if owner is not None and getattr(owner, "fwd_from", None) is not None:
                        forwarded = True
        except Exception:
            pass
        return "\n".join(parts), forwarded

    @staticmethod
    def _is_self(account, dialog_id):
        try:
            me = get_user_config(account).getCurrentUser()
            return me is not None and int(me.id) == int(dialog_id)
        except Exception:
            return False

    @staticmethod
    def _is_contact(account, entity):
        if not hasattr(entity, "first_name"):
            return False
        try:
            return bool(get_contacts_controller(account).isContact(int(entity.id)))
        except Exception:
            return False

    @staticmethod
    def _is_group(entity):
        return hasattr(entity, "title") and not bool(getattr(entity, "broadcast", False))

    def _pick_target(self, account, controller, chat, sender_id):
        """Score the sender inside groups; the chat itself elsewhere."""
        target = chat
        if sender_id and self._is_group(chat):
            sender = controller.getUserOrChat(int(sender_id))
            if sender is not None and not self._is_self(account, sender_id):
                target = sender

        # Telegram's own flags on the container chat always win.
        if bool(getattr(chat, "scam", False)) or bool(getattr(chat, "fake", False)):
            target = chat
        return target

    def _recently_warned(self, account, dialog_id, window=RECENT_WARNING_WINDOW):
        now = time.monotonic()
        cache = getattr(self, "_recent", None)
        if cache is None:
            cache = self._recent = {}

        if len(cache) > 200:
            cutoff = now - window
            for key, stamp in list(cache.items()):
                if stamp < cutoff:
                    del cache[key]

        key = (int(account), int(dialog_id))
        last = cache.get(key)
        cache[key] = now
        return last is not None and (now - last) < window

    # -- settings -----------------------------------------------------------

    def _threshold(self):
        try:
            index = int(self.get_setting("sensitivity", 1))
        except (TypeError, ValueError):
            index = 1
        index = max(0, min(2, index))
        return SENSITIVITY_THRESHOLDS[index]

    def _extra_keywords(self):
        try:
            raw = self.get_setting("extra_keywords", "") or ""
            return [word.strip().lower() for word in str(raw).split(",") if word.strip()]
        except Exception:
            return []

    def create_settings(self):
        return [
            Header(text="Detection"),
            Switch(
                key="auto_check",
                text="Check incoming messages",
                default=True,
                subtext="Warn me when a new message scores above the threshold.",
                icon="msg_info",
            ),
            Selector(
                key="sensitivity",
                text="Sensitivity",
                default=1,
                items=["Low", "Medium", "High"],
                subtext="High catches more but may flag legitimate chats.",
                icon="msg_settings",
            ),
            Switch(
                key="ignore_contacts",
                text="Ignore contacts",
                default=True,
                subtext="Never warn about people in your contact list.",
                icon="msg_contacts",
            ),
            Input(
                key="extra_keywords",
                text="Extra keywords",
                default="",
                subtext="Comma-separated words that add to the spam score.",
                icon="msg_text",
            ),
            Divider(text="Tools"),
            Text(
                text="Scan all chats now",
                subtext="Check your chat list for suspicious chats.",
                icon="msg_search",
                on_click=self._on_scan_click,
            ),
            Text(
                text="How scoring works",
                icon="msg_arrow_forward",
                create_sub_fragment=self._help_page,
            ),
        ]

    def _help_page(self):
        return [
            Header(text="How scoring works"),
            Text(text="Scores add up from chat metadata, message text, links and formatting."),
            Text(text="Telegram's own scam and fake flags weigh the most."),
            Text(text="A high score is a hint, not proof — verify before reporting or blocking."),
            Text(text="Everything runs on-device. No data leaves the app."),
        ]
