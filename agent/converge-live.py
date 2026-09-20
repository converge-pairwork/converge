#!/usr/bin/env python3
"""CONVERGE live renderer: a PostToolUse hook for AI hosts (Claude Code, Codex).

The host runs this each time the converge_session tool returns, while the AI's turn is still
going on. It shows that result's `live` text to the user at once (the hook's systemMessage) and
records the piece's id for the bridge, which then knows the user saw it. Whatever is not recorded
here, the bridge carries into its next display, so a missing or failing hook loses nothing.
No third-party dependencies; reads the hook input on stdin, never the network.
"""
import json
import os
from pathlib import Path
import re
import stat
import sys


def find_live(value):
    """The bridge's result is JSON text somewhere inside the host's tool_response."""
    if isinstance(value, str):
        if '"live"' not in value:
            return None
        try:
            doc = json.loads(value)
        except ValueError:
            return None
        live = doc.get('live') if isinstance(doc, dict) else None
        return live if isinstance(live, dict) else None
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        for item in value:
            found = find_live(item)
            if found:
                return found
    return None


def reparse_point(info):
    """A symbolic link, or on Windows also a junction or any other reparse point: something whose
    name may not lead where it appears to. Everything here refuses to follow one."""
    if stat.S_ISLNK(info.st_mode):
        return True
    attrs = getattr(info, 'st_file_attributes', 0)
    return bool(attrs & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))


def private_to_us(info):
    """Is this directory this user's own and nobody else's? On Unix that is a question about the
    owner and the mode, and both are asked. Windows has neither, and the directory in question is
    inside %LOCALAPPDATA%, which the platform already keeps per-user; there is no cheap check
    that adds anything there, so the shape checks above carry it."""
    if os.name == 'nt':
        return True
    return info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077


def record(ack, piece_id):
    # Only ever a "<process id>.ack" inside a "live" directory that belongs to this user. The
    # bridge builds this path out of its own state directory and its own process id; nothing a
    # remote party sends ever reaches it. The checks are here anyway, because a renderer that
    # writes where it is told is a renderer that can be told anywhere.
    path = Path(ack)
    if not re.fullmatch(r'\d+\.ack', path.name) or path.parent.name != 'live':
        return
    try:
        here = os.lstat(path.parent)
        if not stat.S_ISDIR(here.st_mode) or reparse_point(here) or not private_to_us(here):
            return
        if path.exists() or path.is_symlink():
            mine = os.lstat(path)
            if not stat.S_ISREG(mine.st_mode) or reparse_point(mine):
                return
    except OSError:
        return
    # O_NOFOLLOW is the Unix way to refuse a symlink at open time and does not exist on Windows,
    # where the lstat above is what stands in for it.
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as out:
        out.write('%d\n' % piece_id)


def main():
    try:
        # The display carries box-drawing characters and whatever the two AIs wrote. A Windows
        # console defaults to a code page that cannot encode most of that, and the write would
        # raise rather than print. Say UTF-8 on both streams before anything is read or written.
        for stream in (sys.stdin, sys.stdout):
            if hasattr(stream, 'reconfigure'):
                stream.reconfigure(encoding='utf-8', errors='replace')
        event = json.load(sys.stdin)
        if not str(event.get('tool_name', '')).endswith('converge_session'):
            return 0
        live = find_live(event.get('tool_response'))
        if not live or not isinstance(live.get('text'), str) or not isinstance(live.get('id'), int):
            return 0
        sys.stdout.write(json.dumps({'systemMessage': live['text']}) + '\n')
        sys.stdout.flush()
        if isinstance(live.get('ack'), str):
            record(live['ack'], live['id'])
    except Exception:       # a renderer must never break the tool call it watches
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
