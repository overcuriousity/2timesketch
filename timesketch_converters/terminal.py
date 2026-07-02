#!/usr/bin/env python3
"""Terminal UI primitives for the 2timesketch converter suite.

Draws visual inspiration from TraceVector's web interface: warm off-white /
deep blue-black surfaces, a teal accent, purple highlights, subtle borders,
monospace technical values, and rounded-corner panels translated into box-
drawing characters for the terminal.

All output is written to stderr so stdout remains the converted data stream.
Colors and Unicode box drawing are automatically disabled when stderr is not
a TTY or when NO_COLOR is set.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from contextlib import contextmanager
from typing import Any, Iterator


def _detect_dark_background() -> bool:
    """Best-effort terminal background detection."""
    colorfgbg = os.environ.get("COLORFGBG", "")
    if colorfgbg:
        parts = colorfgbg.split(";")
        if len(parts) >= 2:
            try:
                bg = int(parts[-1])
                # Light backgrounds: 7 (white), 15 (bright white), 230-255 grays.
                if bg in (7, 15) or (230 <= bg <= 255):
                    return False
                return True
            except ValueError:
                pass
    # Default to a dark-friendly theme, which is common for incident-response
    # terminals and reads well on the deep blue-black TraceVector dark base.
    return True


class Theme:
    """ANSI escape sequence colour palette."""

    def __init__(self, dark: bool = True, enabled: bool = True):
        self.dark = dark
        self.enabled = enabled

        if not enabled:
            for attr in (
                "accent",
                "accent_dim",
                "purple",
                "success",
                "warning",
                "danger",
                "info",
                "primary",
                "secondary",
                "muted",
                "reset",
                "bold",
                "dim",
            ):
                setattr(self, attr, "")
            return

        self.reset = "\033[0m"
        self.bold = "\033[1m"
        self.dim = "\033[2m"

        if dark:
            self.accent = "\033[96m"        # bright cyan / teal
            self.accent_dim = "\033[38;5;67m"
            self.purple = "\033[95m"        # bright magenta / TraceVector purple
            self.success = "\033[92m"
            self.warning = "\033[93m"
            self.danger = "\033[91m"
            self.info = "\033[94m"
            self.primary = "\033[97m"
            self.secondary = "\033[37m"
            self.muted = "\033[90m"
        else:
            self.accent = "\033[36m"        # cyan
            self.accent_dim = "\033[38;5;31m"
            self.purple = "\033[35m"
            self.success = "\033[32m"
            self.warning = "\033[33m"
            self.danger = "\033[31m"
            self.info = "\033[34m"
            self.primary = "\033[30m"
            self.secondary = "\033[90m"
            self.muted = "\033[37m"


class BoxChars:
    """Box-drawing character set with an ASCII fallback."""

    def __init__(self, unicode: bool = True):
        if unicode:
            self.h = "─"
            self.v = "│"
            self.tl = "┌"
            self.tr = "┐"
            self.bl = "└"
            self.br = "┘"
            self.ltee = "├"
            self.rtee = "┤"
            self.ttee = "┬"
            self.btee = "┴"
            self.bullet = "◆"
            self.dot = "·"
            self.arrow = "→"
            self.check = "✓"
            self.cross = "✗"
            self.warn = "▲"
        else:
            self.h = "-"
            self.v = "|"
            self.tl = "+"
            self.tr = "+"
            self.bl = "+"
            self.br = "+"
            self.ltee = "+"
            self.rtee = "+"
            self.ttee = "+"
            self.btee = "+"
            self.bullet = "*"
            self.dot = "."
            self.arrow = "->"
            self.check = "[ok]"
            self.cross = "[x]"
            self.warn = "[!]"


class TerminalUI:
    """A lightweight, styled terminal UI for converter runs."""

    def __init__(self, file: Any = None, force_color: bool | None = None, force_unicode: bool | None = None):
        self.file = file or sys.stderr
        self._is_tty = hasattr(self.file, "isatty") and self.file.isatty()
        no_color_env = os.environ.get("NO_COLOR")
        if force_color is True:
            self._enabled = True
        elif force_color is False:
            self._enabled = False
        else:
            self._enabled = self._is_tty and not no_color_env
        self._unicode = (
            self._supports_unicode() if force_unicode is None else force_unicode
        ) and not os.environ.get("ASCII_UI")
        self.theme = Theme(dark=_detect_dark_background(), enabled=self._enabled)
        self.box = BoxChars(unicode=self._unicode)

    def _supports_unicode(self) -> bool:
        term = os.environ.get("TERM", "")
        if "utf" in term.lower():
            return True
        if self._is_tty and any(
            name in term.lower() for name in ("xterm", "kitty", "alacritty", "screen", "tmux")
        ):
            return True
        return False

    @property
    def width(self) -> int:
        try:
            return shutil.get_terminal_size().columns
        except Exception:
            return 80

    def _write(self, text: str) -> None:
        self.file.write(text)
        self.file.flush()

    def _line(self, text: str = "") -> None:
        self._write(text + "\n")

    @staticmethod
    def strip_ansi(text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)

    def _visible_len(self, text: str) -> int:
        return len(self.strip_ansi(text))

    def _pad(self, text: str, width: int, fill: str = " ") -> str:
        visible = self._visible_len(text)
        if visible >= width:
            return text
        return text + fill * (width - visible)

    def _truncline(self, text: str, width: int) -> str:
        visible = self._visible_len(text)
        if visible <= width:
            return text
        # Walk backwards to find a safe truncation point before the limit.
        plain = self.strip_ansi(text)
        if len(plain) <= width - 1:
            return text
        return plain[: max(width - 1, 0)] + "…"

    def _color(self, text: str, color: str) -> str:
        if not self._enabled:
            return text
        return f"{color}{text}{self.theme.reset}"

    def badge(self, text: str, variant: str = "accent") -> str:
        """Return an inline badge string styled like TraceVector's ``Badge``."""
        color_map = {
            "accent": self.theme.accent,
            "purple": self.theme.purple,
            "success": self.theme.success,
            "warning": self.theme.warning,
            "danger": self.theme.danger,
            "info": self.theme.info,
            "muted": self.theme.muted,
        }
        color = color_map.get(variant, self.theme.accent)
        if not self._enabled:
            return f"[{text}]"
        return self._color(f"{self.box.bullet} {text}", color)

    def header(
        self,
        title: str,
        subtitle: str | None = None,
        badges: list[tuple[str, str]] | None = None,
        version: str | None = None,
    ) -> None:
        """Render a top banner panel."""
        if not self._enabled:
            self._line(f"{title} {subtitle or ''}".strip())
            return

        b = self.box
        t = self.theme
        w = min(self.width, 80)

        logo = self._color("◆", t.purple)
        head = f"{logo} {self._color(title, t.bold + t.primary)}"
        if version:
            head += self._color(f"  v{version}", t.muted)

        lines: list[str] = [head]
        if subtitle:
            lines.append(self._color(subtitle, t.secondary))
        if badges:
            badge_str = "  ".join(self.badge(text, variant) for text, variant in badges)
            lines.append(badge_str)

        inner_width = w - 2
        self._line(b.tl + b.h * inner_width + b.tr)
        for line in lines:
            self._line(b.v + self._pad(self._truncline(line, inner_width), inner_width) + b.v)
        self._line(b.bl + b.h * inner_width + b.br)

    def step(self, label: str, message: str = "") -> None:
        """Render a single step line with an accent bullet."""
        bullet = self._color(self.box.bullet, self.theme.accent)
        if message:
            self._line(f"{bullet} {self._color(label, self.theme.primary)} {message}")
        else:
            self._line(f"{bullet} {self._color(label, self.theme.primary)}")

    def log(self, message: str) -> None:
        """Render a plain log line with muted indentation."""
        prefix = self._color(f"{self.box.dot} ", self.theme.muted) if self._enabled else ""
        self._line(f"{prefix}{message}")

    def progress(self, current: int, total: int, label: str = "", width: int = 28) -> None:
        """Render a determinate progress bar."""
        if total <= 0:
            return
        ratio = max(0.0, min(1.0, current / total))
        filled = int(width * ratio)
        empty = width - filled
        if self._enabled:
            bar = self._color(self.box.h * filled, self.theme.accent) + " " * empty
        else:
            bar = self.box.h * filled + " " * empty
        pct = int(ratio * 100)
        line = f"[{bar}] {pct:3d}%  {current}/{total}"
        if label:
            line += f"  {label}"
        if self._enabled:
            self._write(f"\r{line}")
        else:
            self._line(line)

    def end_progress(self) -> None:
        """Finish a progress bar line started with ``progress``."""
        if self._enabled:
            self._line()

    @contextmanager
    def spinner(self, message: str = "Working") -> Iterator[None]:
        """Display an indeterminate spinner around a block of work.

        The spinner is written directly to the terminal and is automatically
        cleared when the block exits.
        """
        if not self._enabled or not self._is_tty:
            self.log(message)
            yield
            return

        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        stop = False

        def _spin() -> None:
            idx = 0
            while not stop:
                frame = frames[idx % len(frames)]
                colored = self._color(frame, self.theme.accent)
                self.file.write(f"\r{colored} {self._color(message, self.theme.secondary)}")
                self.file.flush()
                idx += 1
                # Short sleep; interrupted by the event set in the finally block.
                import time
                time.sleep(0.08)
            # Clear the spinner line.
            self.file.write("\r" + " " * (self._visible_len(message) + 2) + "\r")
            self.file.flush()

        import threading
        thread = threading.Thread(target=_spin, daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop = True
            thread.join(timeout=0.5)

    def success(self, message: str) -> None:
        mark = self._color(self.box.check, self.theme.success)
        self._line(f"{mark} {self._color(message, self.theme.primary)}")

    def warning(self, message: str) -> None:
        mark = self._color(self.box.warn, self.theme.warning)
        self._line(f"{mark} {self._color(message, self.theme.warning)}")

    def error(self, message: str) -> None:
        mark = self._color(self.box.cross, self.theme.danger)
        self._line(f"{mark} {self._color(message, self.theme.danger)}")

    def summary(self, title: str, items: dict[str, Any]) -> None:
        """Render a result/summary panel."""
        if not self._enabled:
            self._line(f"{title}:")
            for key, value in items.items():
                self._line(f"  {key}: {value}")
            return

        b = self.box
        t = self.theme
        w = min(self.width, 80)
        inner = w - 2

        self._line(b.tl + b.h * inner + b.tr)
        title_line = self._color(f"{b.dot} {title}", t.bold + t.primary)
        self._line(b.v + self._pad(title_line, inner) + b.v)
        self._line(b.ltee + b.h * inner + b.rtee)

        max_key = max((len(k) for k in items.keys()), default=0)
        for key, value in items.items():
            key_part = self._color(f"{key}", t.muted)
            value_part = self._color(str(value), t.secondary)
            line = f"  {key_part}{' ' * (max_key - len(key))}  {b.arrow}  {value_part}"
            self._line(b.v + self._pad(self._truncline(line, inner), inner) + b.v)

        self._line(b.bl + b.h * inner + b.br)


_terminal: TerminalUI | None = None


def get_terminal(
    file: Any = None,
    force_color: bool | None = None,
    force_unicode: bool | None = None,
) -> TerminalUI:
    """Return the shared terminal UI instance."""
    global _terminal
    if (
        _terminal is None
        or file is not None
        or force_color is not None
        or force_unicode is not None
    ):
        _terminal = TerminalUI(
            file=file, force_color=force_color, force_unicode=force_unicode
        )
    return _terminal
