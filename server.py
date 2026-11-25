#!/usr/bin/env python3
"""A small, dependency-free LAN file transfer server."""

from __future__ import annotations

import argparse
import errno
import functools
import gzip
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import sys
import threading
import time
import uuid
import webbrowser
import zipfile
import zlib
from datetime import datetime
from email.utils import formatdate
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.etree import ElementTree as ET
from urllib.parse import parse_qs, quote, unquote, urlsplit


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_dir() -> Path:
    """Directory that holds index.html (frozen → _MEIPASS; source → beside this file)."""
    if _is_frozen():
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def default_shared_dir() -> Path:
    """User data dir (frozen → beside exe; source → beside this file). Never under _MEIPASS."""
    if _is_frozen():
        return Path(sys.executable).resolve().parent / "shared"
    return Path(__file__).resolve().parent / "shared"


INDEX_FILE = resource_dir() / "index.html"

# 兜底 favicon（页面内已内联 data: 图标，正常浏览器不会请求到这里）
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 44 44">'
    '<rect x="2" y="2" width="40" height="40" rx="10.5" fill="#0A84FF"/>'
    '<path d="M14 29l7-9 4.5 5.5 3-4L31 29z" fill="#fff"/>'
    '<circle cx="16.5" cy="16.5" r="2.6" fill="#fff"/></svg>'
).encode("utf-8")

# Read buffer used when streaming a file out to a client.
CHUNK_SIZE = 4 * 1024 * 1024
# Read buffer used when draining an incoming request body.
RECV_CHUNK = 1024 * 1024

DEFAULT_UPLOAD_CHUNK = 4 * 1024 * 1024
MIN_UPLOAD_CHUNK = 256 * 1024
MAX_UPLOAD_CHUNK = 128 * 1024 * 1024
# Abandoned upload sessions are swept after this many seconds.
UPLOAD_SESSION_TTL = 7 * 24 * 3600
# Shared-file auto-expiry (default off). Distinct from upload-session TTL above.
# --ttl-days / LAN_TRANSFER_TTL_DAYS; 0 = off. Sweep interval overridable via
# FILE_TTL_SWEEP_INTERVAL (seconds, default 3600) for tests.
FILE_TTL_MAX_DAYS = 3650
FILE_TTL_SWEEP_INTERVAL = 3600
UPLOAD_META_LIMIT = 8 * 1024
# Legacy single-request POST /upload is only for small files / scripts.
# Bigger bodies must use the chunked API (init/chunk/complete), which is
# resumable; a whole-body upload of a large file is lost on any hiccup.
LEGACY_UPLOAD_MAX = 32 * 1024 * 1024
# A rejected legacy body is drained (so the client reads our 413 instead of
# a reset) up to this size; beyond it we just close the connection.
LEGACY_UPLOAD_DRAIN_MAX = MAX_UPLOAD_CHUNK
# F3 同文件并发上传互斥：会话在最近 UPLOAD_ACTIVE_WINDOW 秒内被 init 授予或写入
# 过分片即视为「活跃」。不带该 sessionId 的 init 按指纹命中活跃会话时回 409
# conflict（禁止第二个客户端双写）；已 idle 的残留会话仍按 F1 指纹续接。
# 0 = 关闭互斥（回到 F1 行为）。可用环境变量 LAN_UPLOAD_ACTIVE_WINDOW 覆盖（测试用）。
UPLOAD_ACTIVE_WINDOW = 30.0

# Optional access PIN (Feature D)
AUTH_COOKIE = "lan_transfer_session"
AUTH_SESSION_TTL = 30 * 24 * 3600
AUTH_FAIL_LIMIT = 5
AUTH_FAIL_WINDOW = 60
# B 会话吊销：lastActive 刷新节流（秒）
AUTH_ACTIVE_THROTTLE = 5.0
AUTH_PUBLIC_PATHS = frozenset({
    "/",
    "/index.html",
    "/favicon.ico",
    "/api/config",
    "/api/auth/status",
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/logout",
})
# 访问保护 A：guest 一律 403 的写路由（presence 单独按「是否本人」判定）
GUEST_DENIED_POST = frozenset({
    "/upload",
    "/api/clipboard",
    "/api/upload/init",
    "/api/upload/chunk",
    "/api/upload/complete",
    "/delete",
})
GUEST_DENIED_DELETE = frozenset({"/api/clipboard", "/api/upload/session"})

# ① 多端在线态（presence）：纯内存，重启即清空。心跳超过 PRESENCE_TTL 秒
# 未刷新视为离线（读时惰性剔除）。可用环境变量 LAN_PRESENCE_TTL 覆盖（测试用）。
PRESENCE_TTL = 45.0
PRESENCE_NAME_MAX = 16
PRESENCE_MAX_PEERS = 256
PRESENCE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_PRESENCE_CTRL_RE = re.compile(
    "[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]"
)


def sanitize_nickname(raw: object) -> str:
    """去控制/零宽字符 → 折叠空白 → trim → 截断到 PRESENCE_NAME_MAX。空串表示无效。"""
    if not isinstance(raw, str):
        return ""
    text = _PRESENCE_CTRL_RE.sub("", raw)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:PRESENCE_NAME_MAX].strip()


def default_nickname(client_id: str, user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if any(k in ua for k in ("iphone", "ipad", "android", "mobile", "harmonyos")):
        return "手机"
    if any(k in ua for k in ("windows", "macintosh", "mac os x", "x11", "linux", "cros")):
        return "电脑"
    return f"访客{client_id[-4:]}"


def detect_lan_ip() -> str:
    """Return the most useful local IPv4 address available."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return str(sock.getsockname()[0])
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        sock.close()


def validate_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"无效的 IP 地址：{value}") from exc
    if address.version != 4:
        raise argparse.ArgumentTypeError("当前版本仅支持 IPv4 地址")
    return str(address)


FALLBACK_PORTS = (6666,8080, 8866, 9000, 9527, 18080, 8000)


def probe_port(host: str, port: int) -> str | None:
    """启动前预检端口。返回 None 表示可绑定，否则返回人类可读的失败原因。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 与 LanFileServer.allow_reuse_address 对齐：否则 Linux/macOS 上刚关掉服务
    # 立刻重启，残留的 TIME_WAIT 连接会让预检误报「已被占用」（真正的
    # bind 本来能成功）。Windows 的 SO_REUSEADDR 语义是「可抢占在用端口」，
    # 不能开，Windows 上 TIME_WAIT 本也不阻止 bind。
    if os.name != "nt":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        return None
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        if code in {errno.EADDRINUSE, 10048}:
            return "已被其他程序占用"
        if code in {errno.EACCES, 10013}:
            return "位于 Windows 保留端口段（Hyper-V/WSL 等预留），系统禁止绑定"
        if code in {errno.EADDRNOTAVAIL, 10049}:
            return "本机不存在该 IP 地址"
        return str(exc)
    finally:
        sock.close()


def resolve_port(host: str, requested: int | None) -> int | None:
    """解析监听端口。

    - 显式指定端口：不可用时返回 None（由调用方报错退出，不擅自换端口）
    - 默认端口：按 FALLBACK_PORTS 依次预检，取第一个可用端口
    """
    if requested is not None:
        reason = probe_port(host, requested)
        if reason is None:
            return requested
        print(f"端口 {requested} 不可用：{reason}", file=sys.stderr)
        return None
    for port in FALLBACK_PORTS:
        if probe_port(host, port) is None:
            return port
        print(f"端口 {port} 不可用，尝试下一个候选端口……")
    return None


# Windows reserves these device names regardless of extension ("CON.txt" too).
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_filename(raw_name: str) -> str:
    name = unquote(raw_name)
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        raise ValueError("文件名无效")
    stem = name.split(".", 1)[0].strip().upper()
    if stem in _WINDOWS_RESERVED:
        raise ValueError(f"文件名使用了 Windows 保留设备名（{stem}），无法保存")
    if name != name.rstrip(" ."):
        # Windows silently strips trailing dots/spaces when creating the file,
        # which would desync session name vs. on-disk name (resume / instant
        # skip / final rename all break). Reject up front with a clear error.
        raise ValueError("文件名不能以空格或点结尾")
    return name


# F5 文件夹上传：相对路径规则（前端 index.html 同名常量须保持一致）
MAX_REL_DEPTH = 8          # 相对路径最多 8 段（含文件名），即最多 7 层子目录
MAX_REL_PATH_CHARS = 1024  # 整条相对路径字符上限
MAX_SEGMENT_BYTES = 255    # 单段 UTF-8 字节上限（主流文件系统单名上限）
MAX_FOLDER_BATCH = 500     # 单次拖入/选择文件夹最多文件数（前端执行，服务端无批次概念）
# A：多选打包下载。未压缩合计体积上限；JSON body 需容纳最多 500 条路径。
MAX_ZIP_UNCOMPRESSED = 2 * 1024 * 1024 * 1024  # 2 GiB
ZIP_DOWNLOAD_BODY_LIMIT = 600 * 1024


def safe_relpath(raw_name: str) -> str:
    """Validate a client-supplied *relative* path ("dir/sub/a.txt").

    A plain basename passes through exactly like safe_filename(). Multi-segment
    paths use "/" only; rejected: absolute paths, "\\", drive letters / ":",
    empty / "." / ".." segments, hidden (dot-leading) directory segments
    (would reach .uploads / state files), Windows reserved names in any segment,
    trailing dot/space, too deep / too long. Returns the normalised POSIX path.
    """
    name = unquote(raw_name)
    if "\\" in name or "\x00" in name:
        raise ValueError("文件路径无效")
    if name.startswith("/"):
        raise ValueError("不允许绝对路径")
    if len(name) > MAX_REL_PATH_CHARS:
        raise ValueError(f"文件路径过长（上限 {MAX_REL_PATH_CHARS} 字符）")
    parts = name.split("/")
    if len(parts) > MAX_REL_DEPTH:
        raise ValueError(f"目录层级过深（上限 {MAX_REL_DEPTH} 段，含文件名）")
    for index, part in enumerate(parts):
        if part == "..":
            raise ValueError("文件路径不能包含 ..")
        if ":" in part:
            raise ValueError("文件路径不能包含盘符或冒号")
        if len(part.encode("utf-8")) > MAX_SEGMENT_BYTES:
            raise ValueError("文件名或目录名过长")
        if len(parts) > 1 and index < len(parts) - 1 and part.startswith("."):
            raise ValueError("不允许以 . 开头的目录")
        safe_filename(part)  # empty / "." / reserved / trailing dot-space
    return "/".join(parts)


def format_size(num: float | int) -> str:
    """Human readable byte count."""
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    value = float(num)
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024
        index += 1
    return f"{value:.0f} {units[index]}" if index == 0 else f"{value:.2f} {units[index]}"


def is_upload_temporary(path: Path) -> bool:
    """Identify temporary files created by this server during an upload."""
    parts = path.name.rsplit(".", 2)
    if len(parts) != 3 or parts[2] != "part":
        return False
    token = parts[1]
    return len(token) == 32 and all(char in "0123456789abcdef" for char in token)


def _xml_text_nodes(xml: str) -> str:
    """Extract text between <...:t>...</...:t> tags (w:t, a:t, t)."""
    found = re.findall(r"<(?:[\w]+:)?t\b[^>]*>([^<]*)</(?:[\w]+:)?t>", xml)
    return "".join(found)


def _extract_ooxml_text(path: Path, ext: str) -> str:
    """Pull readable text out of a .docx/.xlsx/.pptx file using only stdlib."""
    parts: list[str] = []
    with zipfile.ZipFile(path) as zf:
        if ext == "docx":
            xml = zf.read("word/document.xml").decode("utf-8", errors="replace")
            for para in re.split(r"</w:p>", xml):
                t = _xml_text_nodes(para)
                if t.strip():
                    parts.append(t)
        elif ext == "xlsx":
            shared = [n for n in zf.namelist() if n == "xl/sharedStrings.xml"]
            if shared:
                xml = zf.read(shared[0]).decode("utf-8", errors="replace")
                for si in re.split(r"</si>", xml):
                    t = _xml_text_nodes(si)
                    if t.strip():
                        parts.append(t)
            for n in zf.namelist():
                if re.match(r"xl/worksheets/sheet\d+\.xml$", n):
                    xml = zf.read(n).decode("utf-8", errors="replace")
                    for row in re.split(r"</row>", xml):
                        t = _xml_text_nodes(row)
                        if t.strip():
                            parts.append(t)
        elif ext == "pptx":
            for n in sorted(zf.namelist()):
                if re.match(r"ppt/slides/slide\d+\.xml$", n):
                    xml = zf.read(n).decode("utf-8", errors="replace")
                    for para in re.split(r"</a:p>", xml):
                        t = _xml_text_nodes(para)
                        if t.strip():
                            parts.append(t)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Office OOXML -> HTML  (zero-dependency, preserves basic layout/formatting)
# ---------------------------------------------------------------------------

def _ln(tag: str) -> str:
    """Local name of a (possibly namespaced) ElementTree tag."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _kids(elem: ET.Element, local: str) -> list[ET.Element]:
    """Direct children of *elem* whose local tag name is *local*."""
    return [c for c in elem if _ln(c.tag) == local]


def _first(elem: ET.Element | None, local: str) -> ET.Element | None:
    """First direct child with local tag *local* (or None)."""
    if elem is None:
        return None
    for c in elem:
        if _ln(c.tag) == local:
            return c
    return None


def _attr(elem: ET.Element | None, local: str) -> str | None:
    """Value of the attribute named *local* regardless of namespace (or None)."""
    if elem is None:
        return None
    for key, value in elem.attrib.items():
        if _ln(key) == local:
            return value
    return None


def _iter_local(elem: ET.Element, local: str):
    """Yield all descendants (and *elem* itself) with local tag *local*."""
    for node in elem.iter():
        if _ln(node.tag) == local:
            yield node



def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _run_text(r: ET.Element):
    """Yield ('text', s) | ('br', '') | ('tab', '') | ('img', '') segments."""
    for node in r.iter():
        tag = _ln(node.tag)
        if tag == "t":
            yield ("text", node.text or "")
        elif tag in ("br", "cr"):
            yield ("br", "")
        elif tag == "tab":
            yield ("tab", "")
        elif tag in ("drawing", "pict", "object"):
            yield ("img", "")


def _render_runs(p: ET.Element) -> str:
    """Render a paragraph's runs into HTML, keeping basic inline formatting."""
    out = []
    for r in _kids(p, "r"):
        rpr = _first(r, "rPr")
        bold = italic = underline = False
        color = size = None
        if rpr is not None:
            for tag, flag in (("b", "bold"), ("i", "italic"), ("u", "underline")):
                el = _first(rpr, tag)
                if el is not None:
                    val = _attr(el, "val")
                    set_val = val in (None, "true", "1", "on")
                    if flag == "bold":
                        bold = set_val
                    elif flag == "italic":
                        italic = set_val
                    else:
                        underline = set_val
            color = _attr(_first(rpr, "color"), "val")
            sz = _attr(_first(rpr, "sz"), "val")
            if sz:
                try:
                    size = int(sz) / 2  # half-points -> pt
                except ValueError:
                    size = None
        text = ""
        for kind, val in _run_text(r):
            if kind == "text":
                text += _esc(val)
            elif kind == "br":
                text += "<br>"
            elif kind == "tab":
                text += "&nbsp;&nbsp;&nbsp;&nbsp;"
            else:
                text += "[图片]"
        if not text:
            continue
        style = ""
        if bold:
            style += "font-weight:700;"
        if italic:
            style += "font-style:italic;"
        if underline:
            style += "text-decoration:underline;"
        if color and color not in ("auto", "000000", "000"):
            style += f"color:#{color};"
        if size:
            style += f"font-size:{size}pt;"
        out.append(f'<span style="{style}">{text}</span>' if style else text)
    return "".join(out)


def _heading_level(style_id: str | None, style_name: str | None) -> int | None:
    if style_id:
        m = re.search(r"(\d)$", style_id)
        if style_id.lower().startswith("heading") and m:
            return min(int(m.group(1)), 6)
    if style_name:
        m = re.search(r"heading\s*(\d)|标题\s*(\d)", style_name, re.I)
        if m:
            return min(int(m.group(1) or m.group(2)), 6)
        if style_name.lower() in ("title", "标题"):
            return 1
    return None


def _docx_to_html(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        root = ET.fromstring(zf.read("word/document.xml"))
        styles_xml = zf.read("word/styles.xml") if "word/styles.xml" in names else None
        numbering_xml = (
            zf.read("word/numbering.xml") if "word/numbering.xml" in names else None
        )

    style_names: dict[str, str] = {}
    if styles_xml:
        sroot = ET.fromstring(styles_xml)
        for st in _iter_local(sroot, "style"):
            sid = _attr(st, "styleId")
            nm = _attr(_first(st, "name"), "val")
            if sid and nm:
                style_names[sid] = nm

    num_fmts: dict[str, dict[int, str]] = {}
    abstract_of_num: dict[str, str] = {}
    if numbering_xml:
        nroot = ET.fromstring(numbering_xml)
        for an in _iter_local(nroot, "abstractNum"):
            aid = _attr(an, "abstractNumId")
            fmts: dict[int, str] = {}
            for lv in _kids(an, "lvl"):
                ilvl = int(_attr(lv, "ilvl") or "0")
                fmts[ilvl] = _attr(_first(lv, "numFmt"), "val") or "decimal"
            num_fmts[aid] = fmts
        for nm in _iter_local(nroot, "num"):
            nid = _attr(nm, "numId")
            aid = _attr(_first(nm, "abstractNumId"), "val")
            if nid is not None and aid is not None:
                abstract_of_num[nid] = aid

    body = _first(root, "body")
    if body is None:
        return "<p>（文档为空）</p>"

    def para_info(p: ET.Element):
        ppr = _first(p, "pPr")
        style_id = jc = None
        ilvl = num_id = None
        if ppr is not None:
            ps = _first(ppr, "pStyle")
            if ps is not None:
                style_id = _attr(ps, "val")
            jc_el = _first(ppr, "jc")
            if jc_el is not None:
                jc = _attr(jc_el, "val")
            numpr = _first(ppr, "numPr")
            if numpr is not None:
                il = _first(numpr, "ilvl")
                ni = _first(numpr, "numId")
                ilvl = int(_attr(il, "val") or "0")
                num_id = _attr(ni, "val")
        inline = _render_runs(p)
        style = ""
        if jc == "center":
            style += "text-align:center;"
        elif jc == "right":
            style += "text-align:right;"
        elif jc == "both":
            style += "text-align:justify;"
        heading = _heading_level(style_id, style_names.get(style_id)) if style_id else None
        return {
            "inline": inline,
            "style": style,
            "ilvl": ilvl,
            "num_id": num_id,
            "heading": heading,
        }

    def table_html(tbl: ET.Element) -> str:
        rows = []
        for tr in _kids(tbl, "tr"):
            cells = []
            for tc in _kids(tr, "tc"):
                cell_text = (
                    "".join(_render_runs(p) for p in _kids(tc, "p")) or "&nbsp;"
                )
                cells.append(f"<td>{cell_text}</td>")
            rows.append("<tr>" + "".join(cells) + "</tr>")
        return '<table class="doc-table">' + "".join(rows) + "</table>"

    def fmt_for(ilvl: int, num_id: str) -> str:
        aid = abstract_of_num.get(num_id)
        return (num_fmts.get(aid, {}) or {}).get(ilvl, "decimal")

    out: list[str] = []
    stack: list[tuple[int, str]] = []  # (ilvl, list_type)

    def close_all() -> None:
        while stack:
            out.append("</li>")
            out.append(f"</{stack[-1][1]}>")
            stack.pop()

    for child in body:
        local = _ln(child.tag)
        if local == "p":
            info = para_info(child)
            if info["num_id"] not in (None, "0"):
                fmt = fmt_for(info["ilvl"], info["num_id"])
                ltype = "ul" if fmt == "bullet" else "ol"
                while stack and stack[-1][0] > info["ilvl"]:
                    out.append(f"</{stack[-1][1]}>")
                    stack.pop()
                if not stack or stack[-1][0] < info["ilvl"]:
                    out.append(f"<{ltype}>")
                    stack.append((info["ilvl"], ltype))
                    out.append("<li>")
                elif stack[-1][1] != ltype:
                    out.append("</li></" + stack[-1][1] + ">")
                    stack.pop()
                    out.append(f"<{ltype}>")
                    stack.append((info["ilvl"], ltype))
                    out.append("<li>")
                else:
                    out.append("</li><li>")
                out.append(info["inline"])
            else:
                close_all()
                if info["heading"]:
                    h = info["heading"]
                    out.append(f"<h{h} style='{info['style']}'>{info['inline']}</h{h}>")
                else:
                    out.append(f"<p style='{info['style']}'>{info['inline']}</p>")
        elif local == "tbl":
            close_all()
            out.append(table_html(child))
    close_all()
    return "".join(out)


def _col_to_index(col: str) -> int:
    idx = 0
    for ch in col:
        idx = idx * 26 + (ord(ch.upper()) - 64)
    return idx - 1


def _xlsx_to_html(path: Path) -> str | None:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            sroot = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in _iter_local(sroot, "si"):
                shared.append(
                    _esc("".join((n.text or "") for n in _iter_local(si, "t")))
                )
        sheets = []
        for n in sorted(names):
            if not re.match(r"xl/worksheets/sheet\d+\.xml$", n):
                continue
            sroot = ET.fromstring(zf.read(n))
            rows = []
            for row in _iter_local(sroot, "row"):
                cells: dict[int, str] = {}
                maxc = -1
                for c in _kids(row, "c"):
                    ref = _attr(c, "r") or ""
                    col = "".join(ch for ch in ref if ch.isalpha())
                    ci = _col_to_index(col) if col else 0
                    t = _attr(c, "t")
                    v = _first(c, "v")
                    is_el = _first(c, "is")
                    val = ""
                    if t == "s" and v is not None:
                        try:
                            val = shared[int(v.text)]
                        except (ValueError, IndexError):
                            val = ""
                    elif is_el is not None:
                        val = _esc("".join(nn.text or "" for nn in _iter_local(is_el, "t")))
                    elif v is not None:
                        val = _esc(v.text or "")
                    if val:
                        cells[ci] = val
                    maxc = max(maxc, ci)
                if maxc >= 0:
                    row_html = "".join(
                        f"<td>{cells.get(i, '&nbsp;')}</td>" for i in range(maxc + 1)
                    )
                    rows.append(f"<tr>{row_html}</tr>")
            if rows:
                sheets.append('<table class="doc-table">' + "".join(rows) + "</table>")
    if not sheets:
        return None
    return '<div class="sheet-stack">' + "".join(sheets) + "</div>"


def _pptx_to_html(path: Path) -> str | None:
    with zipfile.ZipFile(path) as zf:
        slides = []
        for n in sorted(zf.namelist()):
            if not re.match(r"ppt/slides/slide\d+\.xml$", n):
                continue
            sroot = ET.fromstring(zf.read(n))
            paras = []
            for p in _iter_local(sroot, "p"):
                t = _esc("".join((nn.text or "") for nn in _iter_local(p, "t")))
                if t.strip():
                    paras.append(t)
            if paras:
                title = paras[0]
                body = paras[1:]
                html = f"<section class='slide'><h2>{title}</h2>"
                if body:
                    html += "<ul>" + "".join(f"<li>{b}</li>" for b in body) + "</ul>"
                html += "</section>"
                slides.append(html)
    if not slides:
        return None
    return "".join(slides)


def _ooxml_to_html(path: Path, ext: str) -> str | None:
    ext = ext.lower()
    if ext == "docx":
        return _docx_to_html(path)
    if ext == "xlsx":
        return _xlsx_to_html(path)
    if ext == "pptx":
        return _pptx_to_html(path)
    return None


_DOC_CSS = """
:root{color-scheme:light;}
*{box-sizing:border-box;}
body{margin:0;background:#e9e9ee;color:#1c1c1e;
  font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Microsoft YaHei",sans-serif;}
.paper{max-width:820px;margin:22px auto;padding:48px 56px;background:#fff;
  border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,.12);
  font-size:15px;line-height:1.7;word-break:break-word;}
.paper h1,.paper h2,.paper h3,.paper h4,.paper h5,.paper h6{
  line-height:1.3;margin:1.1em 0 .5em;font-weight:700;}
.paper h1{font-size:1.9em;} .paper h2{font-size:1.55em;}
.paper h3{font-size:1.3em;} .paper h4{font-size:1.12em;}
.paper h5{font-size:1em;} .paper h6{font-size:.92em;}
.paper p{margin:.5em 0;}
.paper ul,.paper ol{margin:.4em 0;padding-left:1.6em;}
.paper li{margin:.2em 0;}
.paper table,.doc-table{border-collapse:collapse;width:100%;margin:.8em 0;font-size:14px;}
.paper td,.doc-table td{border:1px solid #d0d0d5;padding:6px 10px;vertical-align:top;}
.paper .slide{border:1px solid #e3e3e8;border-radius:10px;padding:18px 22px;margin:14px 0;}
.paper .slide h2{margin-top:.2em;}
.fallback{white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;
  background:#f6f6f8;padding:16px;border-radius:8px;}
.note{color:#8a8a8e;font-size:14px;padding:24px;text-align:center;line-height:1.7;}
@media (max-width:680px){.paper{padding:24px 18px;margin:0;border-radius:0;}}
"""


def _doc_html_page(inner: str, title: str) -> bytes:
    html = (
        "<!doctype html><html lang='zh-CN'><head>"
        "<meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_esc(title)}</title><style>{_DOC_CSS}</style></head>"
        f"<body><article class='paper'>{inner}</article></body></html>"
    )
    return html.encode("utf-8")


# ---------------------------------------------------------------------------
# Resumable (chunked) upload sessions
# ---------------------------------------------------------------------------
# Each upload gets a session: a ".part" file plus a tiny ".json" sidecar that
# records the final filename / size / client mtime. The received offset is
# *derived from the part file size*, never cached, so a crash or restart can
# never disagree with what is actually on disk.


def uploads_dir(shared_dir: Path) -> Path:
    path = shared_dir / ".uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# 文件列表顺序表
#
# 需求：列表「最新内容置顶」——刚传完的文件排最前，已有项相对顺序稳定，
# 不按文件名 / 大小 / 类型 / 文件自身时间戳（mtime）重排。
#
# 为什么不能用 mtime 排序：complete 阶段会把上传方的 lastModified 写回文件
# （用于秒传判定），于是「传一个 2019 年的老文件」会带着 2019 年的时间插到
# 列表最前面，与它实际的传输时间毫无关系。所以这里单独维护一张递增序号表。
#
# 存放位置：共享目录根下的 .file-order.json，而不是 .uploads/ —— 后者的 *.json
# 被会话生命周期独占：load_upload_sessions() 会删掉任何「不像会话」的 json，
# 定期 sweep 也会按 TTL 清理。以 "." 开头的文件同时被文件列表过滤掉。
# ---------------------------------------------------------------------------
ORDER_FILE_NAME = ".file-order.json"
ORDER_MAX_ENTRIES = 5000
_ORDER_LOCK = threading.Lock()


def order_file_path(shared_dir: Path) -> Path:
    return shared_dir / ORDER_FILE_NAME


def _read_order(shared_dir: Path) -> tuple[dict[str, int], int, dict[str, float]]:
    """Return ({filename: sequence}, last_sequence, {filename: ingested_unix}).

    ingestedAt is optional for backward compatibility with older order files.
    Tolerates a missing/corrupt file.
    """
    try:
        data = json.loads(order_file_path(shared_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, 0, {}
    if not isinstance(data, dict):
        return {}, 0, {}
    raw_items = data.get("items")
    items: dict[str, int] = {}
    if isinstance(raw_items, dict):
        for key, value in raw_items.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                items[str(key)] = int(value)
    counter = data.get("seq")
    if not isinstance(counter, (int, float)) or isinstance(counter, bool):
        counter = max(items.values()) if items else 0
    ingested: dict[str, float] = {}
    raw_ingested = data.get("ingestedAt")
    if isinstance(raw_ingested, dict):
        for key, value in raw_ingested.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                ingested[str(key)] = float(value)
    return items, int(counter), ingested


def _write_order(
    shared_dir: Path,
    items: dict[str, int],
    counter: int,
    ingested_at: dict[str, float] | None = None,
) -> None:
    if ingested_at is None:
        ingested_at = {}
    if len(items) > ORDER_MAX_ENTRIES:
        # 只保留最新的若干条，避免长期运行后顺序表无限膨胀
        items = dict(sorted(items.items(), key=lambda kv: kv[1])[-ORDER_MAX_ENTRIES:])
    # Keep ingestedAt aligned with items (drop orphans / trimmed keys)
    ingested_at = {k: float(v) for k, v in ingested_at.items() if k in items}
    payload: dict = {"seq": counter, "items": items}
    if ingested_at:
        payload["ingestedAt"] = ingested_at
    try:
        order_file_path(shared_dir).write_text(
            json.dumps(payload, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass  # 顺序是展示层的优化，写不进去也不该让上传失败


def assign_file_order(shared_dir: Path, name: str) -> None:
    """Mark *name* as the most recently transferred file (appended last)."""
    with _ORDER_LOCK:
        items, counter, ingested = _read_order(shared_dir)
        counter += 1
        items[name] = counter
        ingested[name] = time.time()
        _write_order(shared_dir, items, counter, ingested)


def drop_file_order(shared_dir: Path, name: str) -> None:
    with _ORDER_LOCK:
        items, counter, ingested = _read_order(shared_dir)
        removed = items.pop(name, None) is not None
        ingested_gone = ingested.pop(name, None) is not None
        if not removed and not ingested_gone:
            return
        _write_order(shared_dir, items, counter, ingested)


# ---------------------------------------------------------------------------
# 剪贴板历史
#
# 旧实现是共享根下一个 .clipboard.txt，只存「最新一条」，谁后发谁覆盖——
# 手机上刚发的内容会被电脑端下一次发送冲掉，且无法追溯来源。这里改成
# .clipboard-history.json：每条记录带来源 IP 与时间戳，最新的排在最前。
#
# 存放位置同样是共享目录根（不是 .uploads/），理由同 .file-order.json：
# .uploads/ 下的 json 归会话生命周期管，会被 sweep 清掉；以 "." 开头还会被
# 文件列表自动过滤，不会污染共享区。
# ---------------------------------------------------------------------------
CLIPBOARD_FILE_NAME = ".clipboard-history.json"
CLIPBOARD_LEGACY_FILE = ".clipboard.txt"
CLIPBOARD_MAX_ITEMS = 50
CLIPBOARD_MAX_CHARS = 100_000
_CLIP_LOCK = threading.Lock()


def clipboard_path(shared_dir: Path) -> Path:
    return shared_dir / CLIPBOARD_FILE_NAME


def _clip_stamp(ts: float | None = None) -> str:
    moment = datetime.fromtimestamp(ts) if ts else datetime.now()
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def _read_clipboard(shared_dir: Path) -> tuple[list[dict], int]:
    """Return ([entry, ...] newest first, seq). Tolerates a missing/corrupt file."""
    items: list[dict] = []
    seq = 0
    try:
        data = json.loads(clipboard_path(shared_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if isinstance(data, dict):
        raw = data.get("items")
        if isinstance(raw, list):
            for entry in raw:
                if not isinstance(entry, dict):
                    continue
                text = entry.get("text")
                if not isinstance(text, str):
                    continue
                items.append(
                    {
                        "id": str(entry.get("id") or ""),
                        "text": text,
                        "ip": str(entry.get("ip") or ""),
                        "time": str(entry.get("time") or ""),
                    }
                )
        raw_seq = data.get("seq")
        if isinstance(raw_seq, (int, float)) and not isinstance(raw_seq, bool):
            seq = int(raw_seq)
    if not seq:
        seq = len(items)
    if items:
        return items, seq

    # 首次运行且存在旧版 .clipboard.txt：原样导入，不让已有内容凭空消失
    legacy = shared_dir / CLIPBOARD_LEGACY_FILE
    if legacy.is_file():
        try:
            text = legacy.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if text.strip():
            try:
                stamp = _clip_stamp(legacy.stat().st_mtime)
                # 导入成功后移除旧文件，否则「清空历史」会被它再次回填
                legacy.unlink()
            except OSError:
                stamp = _clip_stamp()
            return (
                [{"id": "c1", "text": text, "ip": "", "time": stamp}],
                1,
            )
    return items, seq


def _write_clipboard(shared_dir: Path, items: list[dict], seq: int) -> None:
    try:
        clipboard_path(shared_dir).write_text(
            json.dumps({"seq": seq, "items": items[:CLIPBOARD_MAX_ITEMS]}, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass  # 历史是附加能力，写不进去也不该让同步失败


def clipboard_add(shared_dir: Path, text: str, ip: str) -> dict:
    """Append *text* as the newest entry. Returns the stored entry."""
    stamp = _clip_stamp()
    with _CLIP_LOCK:
        items, seq = _read_clipboard(shared_dir)
        # 同一台设备连发相同内容：只刷新时间并置顶，避免刷出一串重复条目
        if items and items[0]["text"] == text and items[0]["ip"] == ip:
            items[0] = dict(items[0], time=stamp)
            entry = items[0]
        else:
            seq += 1
            entry = {"id": f"c{seq}", "text": text, "ip": ip, "time": stamp}
            items.insert(0, entry)
        _write_clipboard(shared_dir, items, seq)
        return entry


def clipboard_remove(shared_dir: Path, entry_id: str) -> bool:
    """Delete one entry. Returns False when *entry_id* is not found."""
    if not entry_id:
        return False
    with _CLIP_LOCK:
        items, seq = _read_clipboard(shared_dir)
        kept = [e for e in items if e["id"] != entry_id]
        if len(kept) == len(items):
            return False
        _write_clipboard(shared_dir, kept, seq)
        return True


def clipboard_clear(shared_dir: Path) -> None:
    with _CLIP_LOCK:
        _write_clipboard(shared_dir, [], 0)


def is_valid_session_id(value: str) -> bool:
    return len(value) == 32 and all(c in "0123456789abcdef" for c in value)


class UploadSession:
    """State for one in-flight resumable upload."""

    __slots__ = (
        "id", "name", "size", "last_modified", "part", "meta", "lock", "last_active", "owner_id"
    )

    def __init__(
        self,
        session_id: str,
        name: str,
        size: int,
        last_modified: float | None,
        directory: Path,
        owner_id: str | None = None,
    ) -> None:
        self.id = session_id
        self.owner_id = owner_id
        self.name = name
        self.size = size
        self.last_modified = last_modified
        self.part = directory / f"{session_id}.part"
        self.meta = directory / f"{session_id}.json"
        self.lock = threading.Lock()
        # time.monotonic() of the last init grant / chunk write; 0 = never
        # (e.g. reloaded from disk after a restart -> idle, resumable).
        self.last_active = 0.0

    def mark_active(self) -> None:
        self.last_active = time.monotonic()

    def active_ago(self) -> float | None:
        """Seconds since last activity, or None if never active."""
        if not self.last_active:
            return None
        return max(0.0, time.monotonic() - self.last_active)

    def is_active(self, window: float) -> bool:
        ago = self.active_ago()
        return window > 0 and ago is not None and ago <= window

    @property
    def offset(self) -> int:
        try:
            return self.part.stat().st_size
        except OSError:
            return 0

    def save_meta(self) -> None:
        payload = {
            "id": self.id,
            "name": self.name,
            "size": self.size,
            "last_modified": self.last_modified,
            "created": time.time(),
            "owner_id": self.owner_id,
        }
        self.meta.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )

    def discard(self) -> None:
        self.part.unlink(missing_ok=True)
        self.meta.unlink(missing_ok=True)


def load_upload_sessions(directory: Path) -> dict[str, UploadSession]:
    """Rebuild in-memory sessions from sidecar files (survives a restart)."""
    sessions: dict[str, UploadSession] = {}
    for meta in sorted(directory.glob("*.json")):
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            session_id = str(data.get("id") or meta.stem)
            name = str(data.get("name") or "")
            size = int(data.get("size") or 0)
        except (OSError, ValueError, TypeError):
            meta.unlink(missing_ok=True)
            continue
        if not name or size <= 0 or not is_valid_session_id(session_id):
            meta.unlink(missing_ok=True)
            continue
        session = UploadSession(
            session_id, name, size, data.get("last_modified"), directory, data.get("owner_id")
        )
        if not session.part.is_file():
            session.discard()  # sidecar without data is worthless
            continue
        sessions[session_id] = session
    return sessions


def sweep_upload_sessions(directory: Path, ttl: int = UPLOAD_SESSION_TTL) -> list[str]:
    """Delete abandoned sessions older than *ttl* seconds. Returns swept ids."""
    cutoff = time.time() - ttl
    removed: list[str] = []
    for meta in directory.glob("*.json"):
        try:
            if meta.stat().st_mtime >= cutoff:
                continue
        except OSError:
            continue
        session_id = meta.stem
        (directory / f"{session_id}.part").unlink(missing_ok=True)
        meta.unlink(missing_ok=True)
        removed.append(session_id)
    return removed


def start_session_sweeper(server: LanFileServer, interval: int = 6 * 3600) -> None:
    """Sweep abandoned uploads periodically while the server keeps running.

    Without this, cleanup only happened at startup — a long-lived server
    accumulated .part files until the disk filled up.
    """
    def loop() -> None:
        while True:
            time.sleep(interval)
            try:
                with server._filesystem_lock:
                    for session in list(server.upload_sessions.values()):
                        if session.is_active(server.upload_active_window):
                            session.meta.touch(exist_ok=True)
                    removed = sweep_upload_sessions(server.uploads_dir)
                    for session_id in removed:
                        server.drop_session(session_id)
            except OSError:
                continue
            if removed:
                print(
                    f"已清理 {len(removed)} 个超过 "
                    f"{UPLOAD_SESSION_TTL // 86400} 天未完成的上传。"
                )

    threading.Thread(target=loop, daemon=True, name="upload-sweeper").start()


def iter_shared_file_relpaths(shared_dir: Path, include_personal: bool = True) -> list[str]:
    """List relative POSIX paths of shareable files (same rules as /api/files)."""
    names: list[str] = []
    try:
        for dirpath, dirnames, filenames in os.walk(shared_dir, followlinks=False):
            rel_dir = Path(dirpath).relative_to(shared_dir)
            depth = 0 if rel_dir == Path(".") else len(rel_dir.parts)
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".") and depth + 1 < MAX_REL_DEPTH
            ]
            for fname in filenames:
                path = Path(dirpath) / fname
                if (
                    fname.startswith(".")
                    or is_upload_temporary(path)
                    or not path.is_file()
                ):
                    continue
                rel = fname if depth == 0 else (rel_dir / fname).as_posix()
                names.append(rel)
    except OSError:
        return names
    personal = shared_dir / ".personal"
    if include_personal and personal.is_dir() and not personal.is_symlink():
        for folder in personal.iterdir():
            if not is_valid_session_id(folder.name) or folder.is_symlink() or not folder.is_dir():
                continue
            for rel in iter_shared_file_relpaths(folder, include_personal=False):
                names.append(f".personal/{folder.name}/{rel}")
    return names


def _prune_empty_parents(shared_dir: Path, file_path: Path) -> None:
    """Remove empty dirs after a file delete; never remove the share root."""
    parent = file_path.parent
    root = shared_dir
    while parent != root and root in parent.parents:
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent


def sweep_expired_shared_files(shared_dir: Path, ttl_days: int) -> list[str]:
    """Delete shared files older than *ttl_days* by ingestedAt (fallback mtime).

    Does not touch dotfiles, clipboard store, or .uploads/ sessions.
    Returns relative paths that were removed.
    """
    if ttl_days <= 0:
        return []
    cutoff = time.time() - ttl_days * 86400.0
    with _ORDER_LOCK:
        _items, _counter, ingested = _read_order(shared_dir)
        ingested_snapshot = dict(ingested)
    removed: list[str] = []
    for rel in iter_shared_file_relpaths(shared_dir):
        path = shared_dir / rel
        if not path.is_file():
            continue
        stamp = ingested_snapshot.get(rel)
        if stamp is None:
            try:
                stamp = path.stat().st_mtime
            except OSError:
                continue
        if stamp > cutoff:
            continue
        try:
            path.unlink()
        except OSError:
            continue
        drop_file_order(shared_dir, rel)
        removed.append(rel)
    return removed


def start_file_ttl_sweeper(server: "LanFileServer", interval: int | None = None) -> None:
    """Periodically expire shared files when --ttl-days is enabled."""
    if getattr(server, "file_ttl_days", 0) <= 0:
        return
    if interval is None:
        try:
            interval = int(os.environ.get("FILE_TTL_SWEEP_INTERVAL", FILE_TTL_SWEEP_INTERVAL))
        except ValueError:
            interval = FILE_TTL_SWEEP_INTERVAL
    interval = max(1, int(interval))

    def loop() -> None:
        while True:
            time.sleep(interval)
            try:
                with server._filesystem_lock:
                    removed = sweep_expired_shared_files(
                        server.shared_dir, server.file_ttl_days
                    )
            except OSError:
                continue
            if removed:
                print(f"已按 TTL 清理 {len(removed)} 个文件")

    threading.Thread(target=loop, daemon=True, name="file-ttl-sweeper").start()


def free_space(path: Path) -> int:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return -1


class LanFileServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def relpath_problem(self, name: str) -> str | None:
        """F5: a validated relpath can still clash with what is on disk.

        Returns a user-facing reason, or None when "shared_dir / name" is a
        writable file location: inside the share after resolving symlinks, no
        parent segment is an existing file, and the target is not a directory.
        """
        root = self.shared_dir.resolve()
        target = self.shared_dir / name
        current = self.shared_dir
        for part in name.split("/")[:-1]:
            current = current / part
            if current.exists() and not current.is_dir():
                return f"路径冲突：「{current.relative_to(self.shared_dir).as_posix()}」已是文件"
        if target.is_dir():
            return "路径冲突：同名目录已存在"
        try:
            resolved_parent = target.parent.resolve()
        except OSError:
            return "文件路径无效"
        if resolved_parent != root and root not in resolved_parent.parents:
            return "文件路径超出共享目录"
        return None

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        shared_dir: Path,
        advertised_ip: str,
        upload_chunk_size: int = DEFAULT_UPLOAD_CHUNK,
        max_upload_size: int | None = None,
        access_pin: str | None = None,
        guest_pin: str | None = None,
        file_ttl_days: int = 0,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.shared_dir = shared_dir
        self.personal_dir = shared_dir / ".personal"
        if self.personal_dir.is_symlink():
            raise ValueError("个人数据目录不能是符号链接")
        self.personal_dir.mkdir(exist_ok=True)
        self.state_path = self.personal_dir / "state.json"
        if self.state_path.is_symlink():
            raise ValueError("账号数据文件不能是符号链接")
        self._state_lock = threading.RLock()
        self._filesystem_lock = threading.RLock()
        try:
            self.account_state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.account_state = {"users": [], "sessions": {}, "folders": []}
        if not isinstance(self.account_state, dict) or not isinstance(self.account_state.get("users"), list) or not isinstance(self.account_state.get("sessions"), dict) or not isinstance(self.account_state.get("folders"), list):
            raise ValueError(f"账号数据文件格式无效：{self.state_path}")
        self.account_state.setdefault("users", [])
        self.account_state.setdefault("sessions", {})
        self.account_state.setdefault("folders", [])
        self.advertised_ip = advertised_ip
        self.upload_chunk_size = upload_chunk_size
        self.max_upload_size = max_upload_size
        self.uploads_dir = uploads_dir(shared_dir)
        self.upload_sessions: dict[str, UploadSession] = load_upload_sessions(
            self.uploads_dir
        )
        self._upload_lock = threading.Lock()
        # F3: serialises init's "find session / create session" step so two
        # near-simultaneous inits for the same file cannot both open sessions.
        self._init_lock = threading.Lock()
        try:
            self.upload_active_window = max(0.0, float(
                os.environ.get("LAN_UPLOAD_ACTIVE_WINDOW", UPLOAD_ACTIVE_WINDOW)
            ))
        except ValueError:
            self.upload_active_window = UPLOAD_ACTIVE_WINDOW
        # Feature D: optional access PIN + HttpOnly session tokens
        self.access_pin = access_pin or None
        # 访问保护 A：只读访客口令。必须同时有 owner pin（parse_args 已校验）；
        # 与 owner pin 相同时视为未启用（一律按 owner 处理）。
        guest_pin = guest_pin or None
        if guest_pin is not None and (not self.access_pin or guest_pin == self.access_pin):
            guest_pin = None
        self.guest_pin = guest_pin
        # token -> {expiry, role, sid, ip, lastActive}；role ∈ {"owner", "guest"}
        # B 会话吊销：sid 是对外短 id（与 token 无推导关系），API 只暴露 sid。
        self.auth_tokens: dict[str, dict] = {}
        self._auth_lock = threading.Lock()
        self._auth_failures: dict[str, list[float]] = {}
        # ① presence: clientId -> {id, nickname, lastSeen}
        self.presence: dict[str, dict] = {}
        self._presence_lock = threading.Lock()
        try:
            self.presence_ttl = max(1.0, float(
                os.environ.get("LAN_PRESENCE_TTL", PRESENCE_TTL)
            ))
        except ValueError:
            self.presence_ttl = PRESENCE_TTL
        # 共享文件自动过期（天）。0 = 关；≥1 按入库时间（ingestedAt）删除。
        # 与 .uploads/ 分片 7 天扫（UPLOAD_SESSION_TTL）互不相干。
        try:
            self.file_ttl_days = max(0, int(file_ttl_days or 0))
        except (TypeError, ValueError):
            self.file_ttl_days = 0
        if self.file_ttl_days > FILE_TTL_MAX_DAYS:
            self.file_ttl_days = FILE_TTL_MAX_DAYS

    def save_account_state(self) -> None:
        with self._state_lock:
            temporary = self.personal_dir / (".state-" + uuid.uuid4().hex + ".tmp")
            try:
                with temporary.open("x", encoding="utf-8") as output:
                    json.dump(self.account_state, output, ensure_ascii=False)
                os.replace(temporary, self.state_path)
            finally:
                temporary.unlink(missing_ok=True)

    def ensure_default_folder(self, user_id: str) -> dict:
        with self._state_lock:
            folders = self.account_state["folders"]
            folder = next((f for f in folders if f.get("ownerId") == user_id and f.get("isDefaultRoot") is True), None)
            if folder is not None:
                folder_id = folder["id"]
                if isinstance(folder_id, str) and is_valid_session_id(folder_id):
                    folder_dir = self.personal_dir / folder_id
                    try:
                        # Inspect the path itself so a dangling link is never treated as missing.
                        folder_dir.lstat()
                    except FileNotFoundError:
                        try:
                            folder_dir.mkdir()
                        except FileExistsError:
                            pass  # The listing still checks what now occupies this path.
                return folder
            folder = {
                "id": uuid.uuid4().hex,
                "name": "我的文件",
                "ownerId": user_id,
                "visibility": "private",
                "sharedWith": [],
                "isDefaultRoot": True,
            }
            (self.personal_dir / folder["id"]).mkdir()
            folders.append(folder)
            try:
                self.save_account_state()
            except Exception:
                folders.remove(folder)
                raise
            return folder

    def account_for_token(self, token: str | None) -> dict | None:
        if not token:
            return None
        key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._state_lock:
            session = self.account_state["sessions"].get(key)
            if not session or session["expires"] < time.time():
                return None
            return next((u for u in self.account_state["users"] if u["id"] == session["userId"]), None)

    def account_for_ip(self, ip: str, old_token: str | None = None) -> dict:
        with self._state_lock:
            users = self.account_state["users"]
            user = next((item for item in users if item.get("ip") == ip), None)
            if user is not None:
                return user
            old_user = self.account_for_token(old_token)
            if old_user is not None and not old_user.get("ip"):
                old_user["ip"] = ip
                old_user["needsNickname"] = False
                try:
                    self.save_account_state()
                except Exception:
                    old_user.pop("ip", None)
                    old_user.pop("needsNickname", None)
                    raise
                return old_user
            user = {"id": uuid.uuid4().hex, "nickname": ip, "ip": ip, "needsNickname": True}
            users.append(user)
            try:
                self.save_account_state()
            except Exception:
                users.remove(user)
                raise
            return user

    def account_login(self, user: dict) -> str:
        token = secrets.token_urlsafe(32)
        key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._state_lock:
            self.account_state["sessions"][key] = {"userId": user["id"], "expires": time.time() + AUTH_SESSION_TTL}
            self.save_account_state()
        return token

    def get_session(self, session_id: str) -> UploadSession | None:
        with self._upload_lock:
            return self.upload_sessions.get(session_id)

    def find_session_by_fingerprint(
        self, name: str, size: int, last_modified: float | None, owner_id: str
    ) -> UploadSession | None:
        """Unfinished session for the same file (name + size + lastModified).

        lastModified must match too (both missing counts as a match) so a
        different file that happens to share name and size never gets its
        bytes spliced onto someone else's partial data. With several
        candidates the one with the most bytes stored wins.
        """
        best: UploadSession | None = None
        best_offset = -1
        with self._upload_lock:
            candidates = list(self.upload_sessions.values())
        for session in candidates:
            if session.owner_id != owner_id:
                continue
            if session.name != name or session.size != size:
                continue
            a, b = session.last_modified, last_modified
            if (a is None) != (b is None):
                continue
            if a is not None and abs(float(a) - float(b)) > 1:
                continue
            if not session.part.is_file():
                continue
            offset = session.offset
            if offset > best_offset:
                best, best_offset = session, offset
        return best

    def put_session(self, session: UploadSession) -> None:
        with self._upload_lock:
            self.upload_sessions[session.id] = session

    def drop_session(self, session_id: str) -> None:
        with self._upload_lock:
            self.upload_sessions.pop(session_id, None)

    def issue_auth_token(self, role: str = "owner", ip: str = "") -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._auth_lock:
            sids = {e["sid"] for e in self.auth_tokens.values()}
            sid = secrets.token_hex(4)
            while sid in sids:
                sid = secrets.token_hex(4)
            self.auth_tokens[token] = {
                "expiry": now + AUTH_SESSION_TTL,
                "role": role,
                "sid": sid,
                "ip": ip,
                "lastActive": now,
            }
        return token

    def list_auth_sessions(self, self_token: str | None) -> list[dict]:
        """B：活跃会话列表（不含 token 原文），最近活跃在前。"""
        now = time.time()
        with self._auth_lock:
            for tok in [t for t, e in self.auth_tokens.items() if e["expiry"] < now]:
                del self.auth_tokens[tok]
            rows = [
                {
                    "id": e["sid"],
                    "role": e["role"],
                    "ipMasked": mask_ip(e["ip"]),
                    "lastActive": int(e["lastActive"] * 1000),
                    "isSelf": tok == self_token,
                }
                for tok, e in self.auth_tokens.items()
            ]
        rows.sort(key=lambda r: (not r["isSelf"], -r["lastActive"]))
        return rows

    def revoke_auth_session(self, sid: str) -> bool:
        with self._auth_lock:
            hit = [t for t, e in self.auth_tokens.items() if e["sid"] == sid]
            for tok in hit:
                del self.auth_tokens[tok]
        return bool(hit)

    def revoke_all_auth_sessions(self) -> int:
        with self._auth_lock:
            n = len(self.auth_tokens)
            self.auth_tokens.clear()
        return n

    def token_role(self, token: str | None) -> str | None:
        """有效 token → "owner"/"guest"；无效/过期 → None。"""
        if not token:
            return None
        now = time.time()
        with self._auth_lock:
            item = self.auth_tokens.get(token)
            if item is None:
                return None
            if item["expiry"] < now:
                self.auth_tokens.pop(token, None)
                return None
            # B：带有效 cookie 的请求刷新最近活跃（节流，避免每个分片都写）
            if now - item["lastActive"] >= AUTH_ACTIVE_THROTTLE:
                item["lastActive"] = now
            return item["role"]

    def validate_auth_token(self, token: str | None) -> bool:
        return self.token_role(token) is not None

    def _presence_prune_locked(self, now: float) -> None:
        cutoff = now - self.presence_ttl
        for cid in [c for c, e in self.presence.items() if e["lastSeen"] < cutoff]:
            del self.presence[cid]

    def presence_owner_token(self, client_id: str) -> str | None:
        with self._presence_lock:
            entry = self.presence.get(client_id)
            return entry.get("authToken") if entry else None

    def presence_touch(
        self, client_id: str, nickname: str | None, user_agent: str,
        auth_token: str | None = None,
    ) -> dict:
        """登记/刷新一个客户端；nickname=None 表示保留已有名（或给默认名）。"""
        now = time.time()
        with self._presence_lock:
            self._presence_prune_locked(now)
            entry = self.presence.get(client_id)
            if entry is None:
                if len(self.presence) >= PRESENCE_MAX_PEERS:
                    oldest = min(self.presence, key=lambda c: self.presence[c]["lastSeen"])
                    del self.presence[oldest]
                entry = {
                    "id": client_id,
                    "nickname": nickname or default_nickname(client_id, user_agent),
                    "lastSeen": now,
                    "authToken": auth_token,
                }
                self.presence[client_id] = entry
            else:
                entry["lastSeen"] = now
                if auth_token and not entry.get("authToken"):
                    entry["authToken"] = auth_token
                if nickname:
                    entry["nickname"] = nickname
            out = dict(entry)
            out.pop("authToken", None)
            return out

    def presence_leave(self, client_id: str) -> None:
        with self._presence_lock:
            self.presence.pop(client_id, None)

    def presence_peers(self, self_id: str | None = None) -> list[dict]:
        now = time.time()
        with self._presence_lock:
            self._presence_prune_locked(now)
            entries = [dict(e) for e in self.presence.values()]
        entries.sort(key=lambda e: (e["id"] != self_id, -e["lastSeen"]))
        return [
            {
                "id": e["id"],
                "nickname": e["nickname"],
                "lastSeen": int(e["lastSeen"] * 1000),
                "isSelf": e["id"] == self_id,
            }
            for e in entries
        ]

    def revoke_auth_token(self, token: str | None) -> None:
        if not token:
            return
        with self._auth_lock:
            self.auth_tokens.pop(token, None)

    def is_auth_rate_limited(self, ip: str) -> bool:
        now = time.time()
        with self._auth_lock:
            stamps = [t for t in self._auth_failures.get(ip, []) if now - t < AUTH_FAIL_WINDOW]
            self._auth_failures[ip] = stamps
            return len(stamps) >= AUTH_FAIL_LIMIT

    def record_auth_failure(self, ip: str) -> None:
        now = time.time()
        with self._auth_lock:
            stamps = [t for t in self._auth_failures.get(ip, []) if now - t < AUTH_FAIL_WINDOW]
            stamps.append(now)
            self._auth_failures[ip] = stamps

    def clear_auth_failures(self, ip: str) -> None:
        with self._auth_lock:
            self._auth_failures.pop(ip, None)

    def pin_role(self, provided: str) -> str | None:
        """先比 owner 再比 guest（相同口令已在 __init__ 折叠为 owner）。"""
        owner_ok = self.pin_matches(provided)
        guest_ok = bool(self.guest_pin) and self._pin_equal(provided, self.guest_pin or "")
        if owner_ok:
            return "owner"
        if guest_ok:
            return "guest"
        return None

    def pin_matches(self, provided: str) -> bool:
        return self._pin_equal(provided, self.access_pin or "")

    @staticmethod
    def _pin_equal(provided: str, expected: str) -> bool:
        a = provided.encode("utf-8")
        b = expected.encode("utf-8")
        if len(a) != len(b):
            hmac.compare_digest(b, b)
            return False
        return hmac.compare_digest(a, b)


def mask_ip(ip: str) -> str:
    """B：会话列表用的模糊 IP。IPv4 末两段 *；IPv6 只留前两组。"""
    ip = (ip or "").strip()
    if ip.startswith("::ffff:") and ip.count(".") == 3:
        ip = ip[len("::ffff:"):]
    if ip.count(".") == 3 and ":" not in ip:
        a, b, _, _ = ip.split(".")
        return f"{a}.{b}.*.*"
    if ":" in ip:
        if ip in {"::1"}:
            return "::1"
        groups = [g for g in ip.split("%")[0].split(":") if g]
        return ":".join(groups[:2]) + ":*:*" if groups else "*"
    return "*" if ip else "unknown"


def describe_request(method: str, target: str) -> str:
    """把请求行翻译成中文动作，命令行日志不用读英文也能扫读。

    纯展示用途：解析失败或命中未知路由时原样退回 "METHOD path"，
    绝不因为翻译逻辑出异常而打断一次真实请求。
    """
    path, _, query = target.partition("?")
    fields = parse_qs(query)

    def shown(raw: str, limit: int = 34) -> str:
        text = unquote(raw or "")
        return text if len(text) <= limit else text[: limit - 1] + "…"

    name = (fields.get("filename") or fields.get("name") or [""])[0]

    if path in {"/", "/index.html"}:
        return "打开页面"
    if path == "/favicon.ico":
        return "获取站点图标"

    if method == "GET":
        if path == "/api/auth/status":
            return "查询口令状态"
        if path == "/api/auth/sessions":
            return "查询登录会话"
        if path == "/api/files":
            return "获取文件列表"
        if path == "/api/config":
            return "获取上传配置"
        if path == "/api/clipboard":
            return "读取剪贴板历史"
        if path == "/api/presence":
            return "查询在线设备"
        if path == "/api/upload/status":
            return "查询续传进度"
        if path == "/api/archive/list":
            return f"解析压缩包「{shown(name)}」"
        if path == "/api/doc/text":
            return f"提取文档正文「{shown(name)}」"
        if path.startswith("/download/"):
            return f"下载文件「{shown(path[len('/download/') :])}」"
        if path.startswith("/preview/doc/"):
            return f"预览文档「{shown(path[len('/preview/doc/') :])}」"
        if path.startswith("/preview/"):
            return f"预览文件「{shown(path[len('/preview/') :])}」"
    elif method == "POST":
        if path == "/api/auth/login":
            return "验证访问口令"
        if path == "/api/auth/logout":
            return "退出访问口令"
        if path == "/api/auth/sessions/revoke":
            return "吊销一个会话"
        if path == "/api/auth/sessions/revoke-all":
            return "吊销全部会话"
        if path == "/upload":
            return f"上传文件「{shown(name)}」" if name else "上传文件"
        if path == "/api/clipboard":
            return "写入剪贴板"
        if path == "/api/presence":
            return "在线心跳"
        if path == "/api/upload/init":
            return "准备上传"
        if path == "/api/upload/chunk":
            return "上传分片"
        if path == "/api/upload/complete":
            return "合并上传分片"
        if path == "/delete":
            return "删除文件"
        if path == "/api/download-zip":
            return "打包下载选中文件"
    elif method == "PATCH":
        if path == "/api/presence":
            return "修改设备昵称"
    elif method == "DELETE":
        if path == "/api/clipboard":
            return "删除剪贴板记录"
        if path == "/api/upload/session":
            return "中止上传"
    return f"{method} {path}"


def filesystem_operation(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        with self.server._filesystem_lock:
            return method(self, *args, **kwargs)
    return wrapped


class RequestHandler(BaseHTTPRequestHandler):
    server: LanFileServer

    # HTTP/1.1 keep-alive: a chunked upload opens hundreds of requests, and
    # re-handshaking TCP for every 4 MB chunk wastes a lot of throughput.
    protocol_version = "HTTP/1.1"
    # Per-socket idle/read timeout (seconds). Generous enough for a large chunk
    # on a slow Wi-Fi link, short enough to reap dead connections.
    timeout = 300

    def log_message(self, format: str, *args: object) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{stamp}] {self.client_address[0]} - {format % args}")


    # 状态码的中文释义，打印在命令行请求日志里，方便非英语用户扫读
    _STATUS_ZH = {
        HTTPStatus.OK: "成功",
        HTTPStatus.PARTIAL_CONTENT: "部分内容",
        HTTPStatus.NOT_MODIFIED: "内容未变更（缓存命中）",
        HTTPStatus.CREATED: "已创建",
        HTTPStatus.NO_CONTENT: "无内容",
        HTTPStatus.BAD_REQUEST: "请求无效",
        HTTPStatus.UNAUTHORIZED: "未授权",
        HTTPStatus.FORBIDDEN: "禁止访问",
        HTTPStatus.TOO_MANY_REQUESTS: "请求过于频繁",
        HTTPStatus.NOT_FOUND: "未找到",
        HTTPStatus.CONFLICT: "冲突",
        HTTPStatus.LENGTH_REQUIRED: "缺少 Content-Length",
        HTTPStatus.REQUEST_ENTITY_TOO_LARGE: "内容超过上限",
        HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE: "范围无效",
        HTTPStatus.INSUFFICIENT_STORAGE: "磁盘空间不足",
        HTTPStatus.INTERNAL_SERVER_ERROR: "服务器错误",
        HTTPStatus.NOT_IMPLEMENTED: "不支持该方法",
        HTTPStatus.SERVICE_UNAVAILABLE: "服务不可用",
    }

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        # 在线心跳每 15s/端一次，成功时不刷命令行；改名与错误照常记录
        if (
            code == 200
            and getattr(self, "command", "") in {"GET", "POST"}
            and urlsplit(getattr(self, "path", "")).path == "/api/presence"
        ):
            return
        label = code
        if isinstance(code, int):
            zh = self._STATUS_ZH.get(code, "")
            label = f"{code} {zh}".strip() if zh else str(code)
        action = describe_request(
            getattr(self, "command", "") or "-", getattr(self, "path", "")
        )
        self.log_message("%s → %s", action, label)

    # 浏览器端错误页汉化。注意：message 会写入 HTTP 状态行（协议要求
    # latin-1 可编码，中文会直接炸掉连接），所以状态行保持英文短语，
    # 中文说明只放进 explain（仅出现在响应体）。
    error_message_format = (
        "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<title>错误 %(code)s</title></head><body>"
        "<h1>请求出错（错误码 %(code)s）</h1>"
        "<p>%(message)s</p><p>%(explain)s</p></body></html>"
    )
    _ERROR_ZH_EXPLAIN = {
        400: "请求格式或参数有误",
        404: "请求的文件或接口不存在",
        405: "该资源不支持此请求方式",
        500: "处理请求时出现异常",
        501: "服务器不支持此 HTTP 方法",
    }

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        if explain is None:
            explain = self._ERROR_ZH_EXPLAIN.get(int(code))
        super().send_error(code, message, explain)

    # -- body helpers ------------------------------------------------------
    def parse_request(self) -> bool:
        # keep-alive 下同一 handler 实例处理多个请求：每个新请求把已读体计数清零，
        # 否则上一请求的计数会让 drain_body() 误判「已读完」而留下残体，下一请求行被污染（501 '{}GET'）。
        self._body_consumed = 0
        return super().parse_request()

    def read_body(self, length: int) -> bytes:
        """Read up to *length* body bytes, recording consumption.

        drain_body() 扣除这里记录的字节数——否则「先读 body 再 fail()」的
        处理器会触发二次排水，rfile.read() 永久阻塞把连接挂死。
        """
        data = self.rfile.read(length)
        self._body_consumed = getattr(self, "_body_consumed", 0) + len(data)
        return data

    def drain_body(self, limit: int = UPLOAD_META_LIMIT * 4) -> bool:
        """Consume any unread request body so the socket stays in sync.

        Returns True when the whole body was consumed (the keep-alive
        connection is safe to reuse). Returns False when the body was too
        large to drain - the caller must then close the connection, because
        the leftover bytes would otherwise be parsed as the next request.
        """
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        if transfer_encoding not in ("", "identity"):
            # Chunked framing can't be drained by Content-Length arithmetic;
            # leftover bytes would be misparsed as the next request, so the
            # only safe move is to close the connection after responding.
            self.close_connection = True
            return False
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            return True
        remaining = length - getattr(self, "_body_consumed", 0)
        if remaining <= 0:
            return True
        if length > limit:
            return False
        while remaining > 0:
            chunk = self.rfile.read(min(RECV_CHUNK, remaining))
            if not chunk:
                self.close_connection = True
                return False
            remaining -= len(chunk)
        return True

    def fail(
        self,
        status: HTTPStatus | int,
        message: str,
        drain_limit: int = UPLOAD_META_LIMIT * 4,
    ) -> None:
        """Reply with an error and close the connection cleanly.

        The body is drained first: replying while bytes are still in flight
        makes the peer reset the socket on Windows (WSAECONNABORTED) instead
        of reading our error message. Draining also keeps the stream aligned
        for the next request on this connection.
        """
        self.drain_body(drain_limit)
        self.send_json(
            status,
            {"status": "error", "message": message},
            {"Connection": "close"},
        )

    def read_json_body(self, limit: int = UPLOAD_META_LIMIT) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.fail(HTTPStatus.LENGTH_REQUIRED, "缺少有效的 Content-Length")
            return None
        if length <= 0 or length > limit:
            self.fail(HTTPStatus.BAD_REQUEST, "请求体长度无效")
            return None
        raw = self.read_body(length)
        if len(raw) != length:
            self.fail(HTTPStatus.BAD_REQUEST, "请求体读取中断")
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.fail(HTTPStatus.BAD_REQUEST, f"请求体不是合法 JSON：{exc}")
            return None
        return data if isinstance(data, dict) else {}

    def content_length(self) -> int | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length <= 0:
            self.fail(HTTPStatus.LENGTH_REQUIRED, "缺少有效的 Content-Length")
            return None
        return length

    def send_bytes(
        self,
        status: int,
        content: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
        cache_control: str = "no-store",
    ) -> None:
        headers = dict(extra_headers or {})
        if cache_control:
            headers.setdefault("Cache-Control", cache_control)
        # gzip：只压文本类负载。媒体与 Range 流（serve_file_content 自行写
        # 响应头）不走这里，不会被误压；小于 1KB 的负载压缩不划算。
        if (
            len(content) > 1024
            and content_type.startswith(("text/", "application/json", "image/svg+xml"))
            and "gzip" in (self.headers.get("Accept-Encoding") or "")
        ):
            content = gzip.compress(content, 6)
            headers["Content-Encoding"] = "gzip"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def send_json(
        self,
        status: int,
        data: object,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if status == HTTPStatus.BAD_REQUEST and str(data.get("message", "")).startswith("无权访问"):
            status = HTTPStatus.FORBIDDEN
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, body, "application/json; charset=utf-8", extra_headers)

    # -- Feature D: optional access PIN ------------------------------------
    def _session_token_from_cookie(self) -> str | None:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(f"{AUTH_COOKIE}="):
                return part.split("=", 1)[1].strip() or None
        return None

    def is_authenticated(self) -> bool:
        return self.current_user() is not None

    def current_user(self) -> dict | None:
        return self.server.account_for_ip(self.client_address[0], self._session_token_from_cookie())

    @staticmethod
    def public_user(user: dict) -> dict:
        return {"id": user["id"], "nickname": user["nickname"], "ip": user.get("ip", ""), "needsNickname": bool(user.get("needsNickname", False))}

    def checked_name(self, raw: str, write: bool = False) -> str:
        name = unquote(raw)
        if name.startswith(".personal/"):
            parts = name.split("/")
            if len(parts) < 2 or not is_valid_session_id(parts[1]):
                raise ValueError("文件夹路径无效")
            if len(parts) > 2:
                safe_relpath("/".join(parts[2:]))
            user = self.current_user()
            with self.server._state_lock:
                folder = next((f for f in self.server.account_state["folders"] if f["id"] == parts[1]), None)
                allowed = bool(folder and user and (folder["ownerId"] == user["id"] or (not folder.get("isDefaultRoot") and not write and (folder["visibility"] == "public" or (folder["visibility"] == "shared" and user["id"] in folder["sharedWith"])))))
            if not allowed:
                raise ValueError("无权访问此文件夹")
            base = (self.server.personal_dir / parts[1]).resolve()
            if base.parent != self.server.personal_dir.resolve():
                raise ValueError("文件夹路径无效")
        else:
            name = safe_relpath(name)
            if any(part.startswith(".") for part in name.split("/")):
                raise ValueError("不允许访问隐藏路径")
            base = self.server.shared_dir.resolve()
        target = (self.server.shared_dir / name).resolve()
        if target != base and base not in target.parents:
            raise ValueError("文件路径超出共享目录")
        if not name.startswith(".personal/") and (target == self.server.personal_dir.resolve() or self.server.personal_dir.resolve() in target.parents):
            raise ValueError("不允许访问个人存储")
        return name

    def auth_role(self) -> str:
        """"owner" | "guest" | "none"。未设口令时人人等同 owner 权限，但 status 报 "none"。"""
        if not self.server.access_pin:
            return "none"
        return self.server.token_role(self._session_token_from_cookie()) or "none"

    def is_guest(self) -> bool:
        return bool(self.server.guest_pin) and self.auth_role() == "guest"

    def deny_guest(self) -> bool:
        """guest 写操作 → 403 并返回 True；调用前须已过 require_auth。"""
        if not self.is_guest():
            return False
        # 与旧 /upload 拒收同策略：≤ 单分片上限的体读完再回 403（客户端稳拿响应），更大则回完即断
        if not self.drain_body(limit=LEGACY_UPLOAD_DRAIN_MAX):
            self.close_connection = True   # 大分片不读完：响应后断开，避免残留字节被当成下一请求
        self.send_json(
            HTTPStatus.FORBIDDEN,
            {"status": "error", "message": "访客只读：无权执行此操作", "code": "guest_readonly"},
        )
        return True

    def require_auth(self) -> bool:
        """Return True when the request may proceed; otherwise send 401."""
        if self.is_authenticated():
            return True
        self.fail(HTTPStatus.UNAUTHORIZED, "需要访问口令")
        return False

    def handle_auth_status(self) -> None:
        user = self.current_user()
        self.send_json(
            HTTPStatus.OK,
            {
                "enabled": False, "required": False,
                "authenticated": True, "role": "owner",
                "guestEnabled": False,
                "user": self.public_user(user),
            },
        )

    def handle_auth_login(self) -> None:
        self.drain_body()
        self.send_json(HTTPStatus.OK, {"ok": True, "user": self.public_user(self.current_user())})

    def handle_auth_register(self) -> None:
        self.handle_profile()

    def handle_profile(self) -> None:
        data = self.read_json_body()
        if data is None:
            return
        nickname = sanitize_nickname(data.get("nickname"))
        if not nickname:
            self.fail(HTTPStatus.BAD_REQUEST, "昵称不能为空（1–16 个字符）")
            return
        with self.server._state_lock:
            user = self.current_user()
            old_nickname = user["nickname"]
            old_needs_nickname = user.get("needsNickname", False)
            user["nickname"] = nickname
            user["needsNickname"] = False
            try:
                self.server.save_account_state()
            except Exception:
                user["nickname"] = old_nickname
                user["needsNickname"] = old_needs_nickname
                raise
        self.send_json(HTTPStatus.OK, {"ok": True, "user": self.public_user(user)})

    def handle_auth_logout(self) -> None:
        token = self._session_token_from_cookie()
        if token:
            with self.server._state_lock:
                self.server.account_state["sessions"].pop(hashlib.sha256(token.encode()).hexdigest(), None)
                self.server.save_account_state()
        # Drain optional body so keep-alive stays aligned
        self.drain_body()
        cookie = f"{AUTH_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
        self.send_json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": cookie})

    # -- B: 会话吊销（仅 owner）-------------------------------------------
    def deny_non_owner_sessions(self) -> bool:
        """调用前须已过 require_auth。guest → 403 guest_readonly。"""
        if self.server.access_pin and self.auth_role() != "owner":
            if self.command == "POST" and not self.drain_body():
                self.close_connection = True
            self.send_json(
                HTTPStatus.FORBIDDEN,
                {"status": "error", "message": "访客只读：无权管理会话", "code": "guest_readonly"},
            )
            return True
        return False

    def handle_sessions_list(self) -> None:
        if self.deny_non_owner_sessions():
            return
        if not self.server.access_pin:
            self.send_json(HTTPStatus.OK, {"enabled": False, "sessions": []})
            return
        sessions = self.server.list_auth_sessions(self._session_token_from_cookie())
        self.send_json(HTTPStatus.OK, {"enabled": True, "sessions": sessions})

    def handle_sessions_revoke(self) -> None:
        if self.deny_non_owner_sessions():
            return
        data = self.read_json_body()
        if data is None:
            return
        sid = str(data.get("id") or "").strip()
        if not sid or not self.server.revoke_auth_session(sid):
            self.fail(HTTPStatus.NOT_FOUND, "会话不存在或已失效")
            return
        self.send_json(HTTPStatus.OK, {"ok": True})

    def handle_sessions_revoke_all(self) -> None:
        if self.deny_non_owner_sessions():
            return
        self.drain_body()
        n = self.server.revoke_all_auth_sessions()
        self.send_json(HTTPStatus.OK, {"ok": True, "revoked": n})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path

        if path in {"/", "/index.html"}:
            self.handle_index()
            return

        if path == "/favicon.ico":
            # 页面内已用 data: URI 内联图标（不发请求），这里兜底拦截外部
            # 直接对 /favicon.ico 的探测，返回可缓存的 SVG，日志不再刷 404。
            self.send_bytes(
                HTTPStatus.OK,
                FAVICON_SVG,
                "image/svg+xml",
                {"Cache-Control": "public, max-age=604800"},
                cache_control="public, max-age=604800",
            )
            return

        if path == "/api/auth/status":
            self.handle_auth_status()
            return


        if path == "/api/config":
            self.handle_config()
            return


        if path not in AUTH_PUBLIC_PATHS and not self.require_auth():
            return

        if path == "/api/users":
            with self.server._state_lock:
                users = [self.public_user(u) for u in self.server.account_state["users"]]
            self.send_json(HTTPStatus.OK, {"users": users})
            return
        if path == "/api/folders":
            self.handle_folders("GET")
            return
        if path == "/api/directories":
            self.handle_directories("GET", parse_qs(parsed.query))
            return

        if path == "/api/files":
            self.handle_file_list()
            return

        if path == "/api/auth/sessions":
            self.handle_sessions_list()
            return

        if path == "/api/clipboard":
            self.handle_clipboard_get()
            return

        if path == "/api/presence":
            self.handle_presence_get(parse_qs(parsed.query))
            return

        if path == "/api/upload/status":
            self.handle_upload_status(parse_qs(parsed.query))
            return

        if path.startswith("/download/"):
            self.handle_download(path[len("/download/") :])
            return

        # NOTE: /preview/doc/ must be checked before the greedy /preview/
        # route, otherwise "doc/<name>" is treated as a file path (and the
        # embedded "/" trips the filename safety check -> 400).
        if path.startswith("/preview/doc/"):
            self.handle_doc_html(path[len("/preview/doc/"):])
            return

        if path.startswith("/preview/"):
            self.handle_preview(path[len("/preview/") :])
            return

        if path == "/api/archive/list":
            self.handle_archive_list(parse_qs(parsed.query))
            return

        if path == "/api/doc/text":
            self.handle_doc_text(parse_qs(parsed.query))
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path

        if path == "/api/auth/login":
            self.handle_auth_login()
            return
        if path == "/api/auth/register":
            self.handle_auth_register()
            return
        if path == "/api/auth/logout":
            self.handle_auth_logout()
            return

        if path not in AUTH_PUBLIC_PATHS and not self.require_auth():
            return

        if path == "/api/folders":
            self.handle_folders("POST")
            return
        if path == "/api/directories":
            self.handle_directories("POST", parse_qs(parsed.query))
            return

        if path in GUEST_DENIED_POST and self.deny_guest():
            return

        if path == "/api/auth/sessions/revoke":
            self.handle_sessions_revoke()
            return
        if path == "/api/auth/sessions/revoke-all":
            self.handle_sessions_revoke_all()
            return

        if path == "/upload":
            self.handle_upload(parse_qs(parsed.query))
            return
        if path == "/api/clipboard":
            self.handle_clipboard_post()
            return
        if path == "/api/presence":
            self.handle_presence_post()
            return

        if path == "/api/upload/init":
            self.handle_upload_init()
            return

        if path == "/api/upload/chunk":
            self.handle_upload_chunk(parse_qs(parsed.query))
            return

        if path == "/api/upload/complete":
            self.handle_upload_complete(parse_qs(parsed.query))
            return

        if path == "/api/download-zip":
            self.handle_download_zip()
            return

        if path == "/delete":
            self.handle_delete()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        if path not in AUTH_PUBLIC_PATHS and not self.require_auth():
            return
        if path == "/api/profile":
            self.handle_profile()
            return
        if path == "/api/folders":
            self.handle_folders("PATCH")
            return
        if path == "/api/directories":
            self.handle_directories("PATCH", parse_qs(parsed.query))
            return
        if path == "/api/presence":
            self.handle_presence_post(require_existing_id=True)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        if path not in AUTH_PUBLIC_PATHS and not self.require_auth():
            return
        if path == "/api/folders":
            self.handle_folders("DELETE", parse_qs(parsed.query))
            return
        if path == "/api/directories":
            self.handle_directories("DELETE", parse_qs(parsed.query))
            return
        if path in GUEST_DENIED_DELETE and self.deny_guest():
            return
        if path == "/api/clipboard":
            self.handle_clipboard_delete(parse_qs(parsed.query))
            return
        if path == "/api/upload/session":
            self.handle_upload_abort(parse_qs(parsed.query))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    @filesystem_operation
    def handle_folders(self, method: str, query: dict | None = None) -> None:
        user = self.current_user()
        data = self.read_json_body() if method in {"POST", "PATCH"} else {}
        if data is None:
            return
        with self.server._state_lock:
            folders = self.server.account_state["folders"]
            users = self.server.account_state["users"]
            if method == "GET":
                self.server.ensure_default_folder(user["id"])
                result = []
                for folder in folders:
                    folder_id = folder["id"]
                    if not isinstance(folder_id, str) or not is_valid_session_id(folder_id):
                        continue
                    folder_dir = self.server.personal_dir / folder_id
                    try:
                        folder_info = folder_dir.lstat()
                    except (FileNotFoundError, NotADirectoryError):
                        continue
                    if (
                        not stat.S_ISDIR(folder_info.st_mode)
                        or getattr(folder_info, "st_reparse_tag", 0) == stat.IO_REPARSE_TAG_MOUNT_POINT
                    ):
                        continue
                    owner = next((u for u in users if u["id"] == folder["ownerId"]), None)
                    if folder["ownerId"] == user["id"] or (not folder.get("isDefaultRoot") and (folder["visibility"] == "public" or (folder["visibility"] == "shared" and user["id"] in folder["sharedWith"]))):
                        result.append({**folder, "isDefaultRoot": bool(folder.get("isDefaultRoot")), "ownerName": owner["nickname"] if owner else "", "ownerIp": owner.get("ip", "") if owner else "", "path": ".personal/" + folder["id"], "canWrite": folder["ownerId"] == user["id"]})
                self.send_json(HTTPStatus.OK, {"folders": result})
                return
            folder_id = str(data.get("id") or (query or {}).get("id", [""])[0])
            folder = next((f for f in folders if f["id"] == folder_id), None)
            if method != "POST" and (not folder or folder["ownerId"] != user["id"]):
                self.send_json(HTTPStatus.FORBIDDEN, {"status": "error", "message": "无权管理此文件夹"})
                return
            if folder and folder.get("isDefaultRoot"):
                self.send_json(HTTPStatus.FORBIDDEN, {"status": "error", "message": "默认个人目录不能修改或删除"})
                return
            if method == "DELETE":
                prefix = ".personal/" + folder_id + "/"
                if any(s.name.startswith(prefix) for s in self.server.upload_sessions.values()):
                    self.send_json(HTTPStatus.CONFLICT, {"status": "error", "message": "文件夹包含未完成上传"})
                    return
                shutil.rmtree(self.server.personal_dir / folder_id, ignore_errors=False)
                folders.remove(folder)
                self.server.save_account_state()
                self.send_json(HTTPStatus.OK, {"status": "success"})
                return
            name = str(data.get("name", folder["name"] if folder else "")).strip()
            visibility = str(data.get("visibility", folder["visibility"] if folder else "private"))
            shared = data.get("sharedWith", folder["sharedWith"] if folder else [])
            try:
                safe_filename(name)
                if name.startswith(".") or visibility not in {"private", "public", "shared"} or not isinstance(shared, list) or any(not isinstance(x, str) or not any(u["id"] == x for u in users) for x in shared):
                    raise ValueError("文件夹设置无效")
                if any(f is not folder and f["ownerId"] == user["id"] and f["name"].casefold() == name.casefold() for f in folders):
                    raise ValueError("文件夹名称已存在")
            except ValueError as exc:
                self.send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})
                return
            if folder is None:
                folder = {"id": uuid.uuid4().hex, "ownerId": user["id"]}
                (self.server.personal_dir / folder["id"]).mkdir()
                folders.append(folder)
            folder.update({"name": name, "visibility": visibility, "sharedWith": list(dict.fromkeys(shared))})
            self.server.save_account_state()
            self.send_json(HTTPStatus.OK, {"status": "success", "folder": {**folder, "isDefaultRoot": False, "ownerName": user["nickname"], "ownerIp": user.get("ip", ""), "path": ".personal/" + folder["id"], "canWrite": True}})

    @filesystem_operation
    def handle_directories(self, method: str, query: dict) -> None:
        data = self.read_json_body() if method in {"POST", "PATCH"} else {}
        if data is None:
            return
        raw_path = str(data.get("path", query.get("path", [""])[0]))
        try:
            if not raw_path and method in {"GET", "POST"}:
                path = ""
                root = self.server.shared_dir
            else:
                path = self.checked_name(raw_path, write=method != "GET")
                root = self.server.shared_dir / path
            if not root.is_dir() or root.is_symlink():
                raise ValueError("目录不存在")
            if method == "GET":
                directories = []
                for child in root.iterdir():
                    if child.name.startswith(".") or child.is_symlink() or not child.is_dir():
                        continue
                    child_path = f"{path}/{child.name}" if path else child.name
                    self.checked_name(child_path)
                    try:
                        self.checked_name(child_path, write=True)
                        can_write = True
                    except ValueError:
                        can_write = False
                    directories.append({"name": child.name, "path": child_path, "canWrite": can_write})
                self.send_json(HTTPStatus.OK, {"directories": directories})
                return
            if method in {"PATCH", "DELETE"} and path.startswith(".personal/") and path.count("/") == 1:
                raise ValueError("请使用顶层文件夹管理接口")
            if method in {"PATCH", "DELETE"} and any(s.name.startswith(path + "/") for s in self.server.upload_sessions.values()):
                raise ValueError("目录包含未完成上传")
            if method == "DELETE":
                shutil.rmtree(root)
            else:
                name = str(data.get("name") or "").strip()
                safe_filename(name)
                if name.startswith(".") or ":" in name:
                    raise ValueError("目录名无效")
                target = (root if method == "POST" else root.parent) / name
                parent_path = path.rpartition("/")[0]
                target_path = f"{path}/{name}" if method == "POST" and path else name if method == "POST" else f"{parent_path}/{name}" if parent_path else name
                self.checked_name(target_path, write=True)
                if target.exists():
                    raise ValueError("目标目录已存在")
                if method == "POST":
                    target.mkdir()
                else:
                    root.rename(target)
                    with _ORDER_LOCK:
                        order, counter, ingested = _read_order(self.server.shared_dir)
                        for mapping in (order, ingested):
                            for old in list(mapping):
                                if old.startswith(path + "/"):
                                    mapping[target_path + old[len(path):]] = mapping.pop(old)
                        _write_order(self.server.shared_dir, order, counter, ingested)
            self.send_json(HTTPStatus.OK, {"status": "success"})
        except (ValueError, OSError) as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})

    def handle_index(self) -> None:
        """Serve the SPA shell with ETag revalidation + gzip.

        Cache-Control: no-cache（必须回源校验，但命中 ETag 时只回 304）——
        页面更新立即可见，重复访问不再重下 86KB。
        """
        if not INDEX_FILE.is_file():
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "index.html 不存在")
            return
        body = INDEX_FILE.read_bytes()
        etag = f'"idx-{zlib.crc32(body):08x}-{len(body)}"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return
        self.send_bytes(
            HTTPStatus.OK,
            body,
            "text/html; charset=utf-8",
            {"ETag": etag},
            cache_control="no-cache",
        )

    def handle_file_list(self) -> None:
        files = []
        files_epoch = 0
        latest_name = None
        try:
            entries: list[tuple[str, Path, os.stat_result]] = []
            root = self.server.shared_dir
            # F5：递归列出子目录（文件夹上传落盘处），name 为 POSIX 相对路径
            # 如 "photos/a.jpg"；根目录文件 name 不变。跳过 . 开头的目录/文件、
            # 不跟随符号链接目录、层级超过 MAX_REL_DEPTH 的不展示。
            for dirpath, dirnames, filenames in os.walk(root):
                rel_dir = Path(dirpath).relative_to(root)
                depth = 0 if str(rel_dir) == "." else len(rel_dir.parts)
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".") and depth + 1 < MAX_REL_DEPTH
                ]
                for fname in filenames:
                    path = Path(dirpath) / fname
                    if (
                        fname.startswith(".")
                        or is_upload_temporary(path)
                        or not path.is_file()
                    ):
                        continue
                    try:
                        stat = path.stat()
                    except OSError:
                        continue  # raced with a delete; skip instead of failing
                    rel = fname if depth == 0 else (rel_dir / fname).as_posix()
                    entries.append((rel, path, stat))
            for folder in self.server.personal_dir.iterdir():
                if not is_valid_session_id(folder.name) or folder.is_symlink() or not folder.is_dir():
                    continue
                for rel in iter_shared_file_relpaths(folder, include_personal=False):
                    path = folder / rel
                    try:
                        entries.append((f".personal/{folder.name}/{rel}", path, path.stat()))
                    except OSError:
                        continue
            # 排序规则：最新内容置顶。序号表仍然只认"传输先后顺序"（complete
            # 时递增），但输出改为倒序：刚传完的文件排在列表最前面，已有项的
            # 相对顺序不受影响。直接拷进目录、没有序号的文件按 mtime 倒序垫底
            # ——它们不属于任何一次网页传输。
            order, order_seq, _ingested = _read_order(self.server.shared_dir)
            external: list[tuple[str, os.stat_result, int]] = []
            transferred: list[tuple[str, os.stat_result, int]] = []
            present: set[str] = set()
            max_mtime_ns = 0
            for rel, path, stat in entries:
                present.add(rel)
                try:
                    ns = int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000)))
                except (OverflowError, ValueError, OSError):
                    ns = 0
                if ns > max_mtime_ns:
                    max_mtime_ns = ns
                seq = order.get(rel)
                if seq is None:
                    external.append((rel, stat, 0))
                else:
                    transferred.append((rel, stat, seq))
            external.sort(key=lambda row: (-row[1].st_mtime, row[0]))
            transferred.sort(key=lambda row: -row[2])
            files = []
            for rel, stat, _ in transferred + external:
                try:
                    self.checked_name(rel)
                except ValueError:
                    continue
                try:
                    self.checked_name(rel, write=True)
                    can_write = True
                except ValueError:
                    can_write = False
                files.append({
                    "name": rel,
                    "size": stat.st_size,
                    "date": datetime.fromtimestamp(stat.st_mtime).strftime(
                        "%Y-%m-%d %H:%M"
                    ),
                    "canWrite": can_write,
                })
            # 在目录里被直接删掉的文件会留下孤儿序号，顺手清掉
            stale = set(order) - present
            if stale:
                with _ORDER_LOCK:
                    current, counter, ingested = _read_order(self.server.shared_dir)
                    for gone in stale:
                        current.pop(gone, None)
                        ingested.pop(gone, None)
                    _write_order(self.server.shared_dir, current, counter, ingested)
            # filesEpoch：目录内容变更戳（保持在 JS 安全整数内）。
            # order_seq 上传必增；count 覆盖删除；mtime 秒覆盖外部落盘。
            files_epoch = (
                int(order_seq) * 1_000_000
                + len(files) * 1_000
                + ((max_mtime_ns // 1_000_000_000) % 1_000)
            )
            latest_name = files[0]["name"] if files else None
        except OSError as exc:
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "message": str(exc)},
            )
            return
        self.send_json(
            HTTPStatus.OK,
            {
                "files": files,
                "filesEpoch": files_epoch,
                "latestName": latest_name,
            },
        )

    def serve_file_content(self, raw_name: str, inline: bool) -> None:
        """Serve a file with HTTP Range support.

        inline=True  -> Content-Disposition: inline  (for in-browser preview)
        inline=False -> Content-Disposition: attachment (force download)
        """
        try:
            name = self.checked_name(raw_name)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})
            return

        path = self.server.shared_dir / name
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            root = self.server.shared_dir.resolve()
            resolved = path.resolve()
        except OSError as exc:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": f"文件路径无效：{exc}"},
            )
            return
        if resolved != root and root not in resolved.parents:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "文件路径超出共享目录"},
            )
            return
        if not resolved.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        path = resolved

        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        try:
            stat = path.stat()
            size = stat.st_size
        except OSError as exc:
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "message": str(exc)},
            )
            return

        ascii_fallback = "download" + Path(name).suffix
        disposition = (
            "inline"
            if inline
            else (
                f'attachment; filename="{ascii_fallback}"; '
                f"filename*=UTF-8''{quote(Path(name).name, safe='')}"
            )
        )

        # 强校验器：大小 + 纳秒 mtime。前端 Range 续传带 If-Range，文件被替换
        # （内容/时间变化）时不再回 206 拼接旧片，而是回 200 整包 → 前端从 0 重下。
        etag = f'"{size:x}-{stat.st_mtime_ns:x}"'
        last_modified = formatdate(stat.st_mtime, usegmt=True)

        start, end = 0, max(0, size - 1)
        partial = False
        range_header = self.headers.get("Range")
        if_range = (self.headers.get("If-Range") or "").strip()
        if range_header and if_range and if_range not in (etag, last_modified):
            range_header = None  # 校验器不匹配 → 忽略 Range，回 200 整个文件
        if range_header and range_header.startswith("bytes="):
            try:
                specs: list[tuple[int, int]] = []
                for part in range_header[len("bytes="):].split(","):
                    part = part.strip()
                    if not part:
                        continue
                    first, _, last = part.partition("-")
                    if first:
                        begin = int(first)
                        finish = int(last) if last else size - 1
                    elif last:
                        # Suffix range "bytes=-N" means the *last* N bytes.
                        begin = max(0, size - int(last))
                        finish = size - 1
                    else:
                        raise ValueError(part)
                    specs.append((begin, min(finish, size - 1)))
                if not specs:
                    raise ValueError("empty range")
                # Merge contiguous/overlapping ranges; we only serve a single
                # span (no multipart/byteranges). Multiple disjoint ranges
                # fall through to a full 200 response, which RFC 9110 allows.
                specs.sort()
                merged_start, merged_end = specs[0]
                for begin, finish in specs[1:]:
                    if begin <= merged_end + 1:
                        merged_end = max(merged_end, finish)
                    else:
                        # Disjoint multi-range: serve the full body instead.
                        start, end, partial = 0, max(0, size - 1), False
                        break
                else:
                    if merged_start >= size or merged_start > merged_end:
                        # Content-Length: 0 is required — under HTTP/1.1
                        # keep-alive a bodyless response without it makes the
                        # client wait forever for bytes that never come.
                        self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                        self.send_header("Content-Range", f"bytes */{size}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    start, end = merged_start, merged_end
                    partial = True
            except (ValueError, IndexError):
                start, end, partial = 0, max(0, size - 1), False

        length = end - start + 1 if size > 0 else 0  # 空文件：Content-Length 0
        status = HTTPStatus.PARTIAL_CONTENT if partial else HTTPStatus.OK
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Disposition", disposition)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", last_modified)
        if partial:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        try:
            with path.open("rb") as file:
                file.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = file.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            # Client vanished mid-transfer: with keep-alive the socket is now
            # unusable, so make sure it is not handed to the next request.
            self.close_connection = True
        except OSError as exc:
            self.close_connection = True
            print(f"发送文件失败 {name}：{exc}", file=sys.stderr)

    def handle_download_zip(self) -> None:
        """Pack selected shared files into one zip (POST /api/download-zip).

        Validates every name before writing headers; missing/out-of-share → 4xx.
        Streams stdlib ZipFile to the response (no Range on the zip itself).
        Guest-allowed (not in GUEST_DENIED_POST).
        """
        data = self.read_json_body(limit=ZIP_DOWNLOAD_BODY_LIMIT)
        if data is None:
            return
        raw_names = data.get("names")
        if not isinstance(raw_names, list) or not raw_names:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "请提供要打包的文件列表 names"},
            )
            return
        if len(raw_names) > MAX_FOLDER_BATCH:
            self.send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "status": "error",
                    "message": f"一次最多打包 {MAX_FOLDER_BATCH} 个文件",
                },
            )
            return

        try:
            root = self.server.shared_dir.resolve()
        except OSError as exc:
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "message": str(exc)},
            )
            return

        entries: list[tuple[str, Path]] = []
        seen: set[str] = set()
        total_size = 0
        for raw in raw_names:
            if not isinstance(raw, str):
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": "names 中每一项须为字符串"},
                )
                return
            try:
                name = self.checked_name(raw)
            except ValueError as exc:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": str(exc)},
                )
                return
            if name in seen:
                continue
            seen.add(name)
            if any(part.startswith(".") for part in (name.split("/")[2:] if name.startswith(".personal/") else name.split("/"))):
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": f"不允许打包隐藏路径：「{name}」"},
                )
                return
            path = self.server.shared_dir / name
            if is_upload_temporary(path):
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": f"不允许打包临时上传文件：「{name}」"},
                )
                return
            if not path.is_file():
                self.send_json(
                    HTTPStatus.NOT_FOUND,
                    {"status": "error", "message": f"文件不存在：「{name}」"},
                )
                return
            try:
                resolved = path.resolve()
            except OSError as exc:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": f"文件路径无效：「{name}」（{exc}）"},
                )
                return
            if resolved != root and root not in resolved.parents:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"status": "error", "message": f"文件路径超出共享目录：「{name}」"},
                )
                return
            if not resolved.is_file():
                self.send_json(
                    HTTPStatus.NOT_FOUND,
                    {"status": "error", "message": f"文件不存在：「{name}」"},
                )
                return
            try:
                size = resolved.stat().st_size
            except OSError as exc:
                self.send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "message": str(exc)},
                )
                return
            total_size += size
            if total_size > MAX_ZIP_UNCOMPRESSED:
                self.send_json(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {
                        "status": "error",
                        "message": "选中文件未压缩合计超过 2 GiB 上限",
                    },
                )
                return
            entries.append((name, resolved))

        if not entries:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "没有可打包的文件"},
            )
            return

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"lan-transfer-{stamp}.zip"
        disposition = (
            f'attachment; filename="{filename}"; '
            f"filename*=UTF-8''{quote(filename, safe='')}"
        )
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", disposition)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        class _ZipOut:
            def __init__(self, wfile) -> None:
                self._wfile = wfile

            def write(self, data: bytes | bytearray) -> int:
                chunk = data if isinstance(data, bytes) else bytes(data)
                self._wfile.write(chunk)
                return len(chunk)

            def flush(self) -> None:
                return None

        try:
            with zipfile.ZipFile(
                _ZipOut(self.wfile),
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
                allowZip64=True,
            ) as zf:
                for arcname, fpath in entries:
                    zf.write(fpath, arcname=arcname)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except OSError as exc:
            self.close_connection = True
            print(f"打包下载失败：{exc}", file=sys.stderr)

    def handle_download(self, raw_name: str) -> None:
        self.serve_file_content(raw_name, inline=False)

    def handle_preview(self, raw_name: str) -> None:
        self.serve_file_content(raw_name, inline=True)

    def handle_archive_list(self, query: dict[str, list[str]]) -> None:
        """List the contents of a zip archive (zero-dependency).

        Only the .zip format is readable via the standard library; rar/7z/tar.gz
        etc. return {"supported": false} so the client can prompt a download.
        """
        raw_name = query.get("name", [""])[0]
        try:
            name = self.checked_name(raw_name)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})
            return

        path = self.server.shared_dir / name
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
        if ext != "zip":
            self.send_json(
                HTTPStatus.OK,
                {
                    "supported": False,
                    "reason": "仅支持预览 .zip 压缩包的内容，请下载后查看",
                },
            )
            return

        try:
            entries: list[dict] = []
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    entries.append(
                        {
                            "path": info.filename,
                            "size": info.file_size,
                            "dir": info.filename.endswith("/"),
                        }
                    )
            self.send_json(
                HTTPStatus.OK,
                {"supported": True, "name": name, "entries": entries},
            )
        except (zipfile.BadZipFile, OSError) as exc:
            self.send_json(
                HTTPStatus.OK,
                {"supported": False, "reason": f"无法读取压缩包：{exc}"},
            )

    def handle_doc_text(self, query: dict[str, list[str]]) -> None:
        """Extract readable text from an Office OOXML document (zero-dependency).

        .docx / .xlsx / .pptx are zip containers of XML; we pull the text nodes
        with the standard library. Legacy binary .doc / .xls / .ppt are not
        supported and return {"supported": false}.
        """
        raw_name = query.get("name", [""])[0]
        try:
            name = self.checked_name(raw_name)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})
            return

        path = self.server.shared_dir / name
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
        if ext not in {"docx", "xlsx", "pptx"}:
            self.send_json(
                HTTPStatus.OK,
                {
                    "supported": False,
                    "reason": "仅支持预览 .docx / .xlsx / .pptx 文本内容，旧版格式请下载后查看",
                },
            )
            return

        try:
            text = _extract_ooxml_text(path, ext)
        except (zipfile.BadZipFile, OSError, KeyError) as exc:
            self.send_json(
                HTTPStatus.OK,
                {"supported": False, "reason": f"无法解析文档：{exc}"},
            )
            return

        self.send_json(
            HTTPStatus.OK,
            {"supported": True, "name": name, "text": text},
        )

    def handle_doc_html(self, raw_name: str) -> None:
        """Render a .docx/.xlsx/.pptx document as a formatted HTML page.

        The browser shows it inside an iframe, so headings, bold/italic,
        alignment, tables and (bullet/numbered) lists are displayed with their
        original layout. Legacy binary .doc/.xls/.ppt are not supported and get
        a friendly HTML notice with a download link. Zero third-party deps.
        """
        try:
            name = self.checked_name(raw_name)
        except ValueError as exc:
            self.send_bytes(
                HTTPStatus.FORBIDDEN if str(exc).startswith("无权访问") else HTTPStatus.BAD_REQUEST,
                _doc_html_page(
                    f"<p class='note'>文件名无效：{_esc(str(exc))}</p>", "错误"
                ),
                "text/html; charset=utf-8",
            )
            return

        path = self.server.shared_dir / name
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
        if ext not in {"docx", "xlsx", "pptx"}:
            self.send_bytes(
                HTTPStatus.OK,
                _doc_html_page(
                    f"<p class='note'>暂不支持“{_esc(name)}”的排版预览，请下载后查看。"
                    "<br>当前仅支持 .docx / .xlsx / .pptx。</p>",
                    name,
                ),
                "text/html; charset=utf-8",
            )
            return

        try:
            inner = _ooxml_to_html(path, ext)
            if not inner or not inner.strip():
                inner = "<p class='note'>（文档中没有可渲染的内容）</p>"
            html = _doc_html_page(inner, name)
        except Exception:
            # Last-resort fallback: show the extracted plain text.
            try:
                text = _extract_ooxml_text(path, ext)
            except Exception:
                text = ""
            html = _doc_html_page(
                f"<pre class='fallback'>{_esc(text) or '（无法解析文档内容）'}</pre>",
                name,
            )
        self.send_bytes(HTTPStatus.OK, html, "text/html; charset=utf-8")

    # ------------------------------------------------------------------
    # Resumable chunked upload
    # ------------------------------------------------------------------
    def handle_config(self) -> None:
        """Advertise transfer capabilities so the client can tune itself."""
        try:
            usage = shutil.disk_usage(self.server.shared_dir)
            free, total = usage.free, usage.total
        except OSError:
            free = total = -1
        self.send_json(
            HTTPStatus.OK,
            {
                "chunkSize": self.server.upload_chunk_size,
                "minChunkSize": MIN_UPLOAD_CHUNK,
                "maxChunkSize": MAX_UPLOAD_CHUNK,
                "maxUploadSize": self.server.max_upload_size,
                "freeSpace": free,
                "totalSpace": total,
                "resumable": True,
                "keepAlive": True,
                # 0 = 关；≥1 = 共享文件保留天数（按入库时间自动删除）
                "ttlDays": int(self.server.file_ttl_days or 0),
            },
        )

    def _session_from_query(self, query: dict[str, list[str]]) -> UploadSession | None:
        session_id = (query.get("sessionId") or [""])[0].strip()
        if not is_valid_session_id(session_id):
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "上传会话 ID 无效"},
            )
            return None
        session = self.server.get_session(session_id)
        if session is None:
            self.send_json(
                HTTPStatus.NOT_FOUND,
                {
                    "status": "error",
                    "message": "上传会话不存在或已被清理，请重新开始",
                    "gone": True,
                },
            )
            return None
        user = self.current_user()
        try:
            if not user or session.owner_id != user["id"]:
                raise ValueError("无权访问上传会话")
            self.checked_name(session.name, write=True)
        except ValueError as exc:
            self.fail(HTTPStatus.FORBIDDEN, str(exc), MAX_UPLOAD_CHUNK)
            return None
        return session

    @filesystem_operation
    def handle_upload_init(self) -> None:
        """Create or resume an upload session.

        Request  {"name", "size", "lastModified"?, "sessionId"?}
        Response {"sessionId", "offset", "size", "chunkSize", "exists"}
        """
        data = self.read_json_body()
        if data is None:
            return

        try:
            name = self.checked_name(str(data.get("name", "")), write=True)
        except ValueError as exc:
            self.send_json(
                HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)}
            )
            return

        try:
            size = int(data.get("size"))
        except (TypeError, ValueError):
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "文件大小无效"},
            )
            return
        if size <= 0:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "空文件无需上传"},
            )
            return

        limit = self.server.max_upload_size
        if limit is not None and size > limit:
            self.send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "status": "error",
                    "message": f"文件超过服务端上限 {format_size(limit)}",
                },
            )
            return

        raw_mtime = data.get("lastModified")
        try:
            last_modified = float(raw_mtime) if raw_mtime is not None else None
        except (TypeError, ValueError):
            last_modified = None

        # Instant-skip: the exact same file (name + size + source timestamp)
        # is already in the share, so there is nothing to transfer. The
        # client can send "force": true to overwrite anyway (retry after a
        # skip, or when the user explicitly wants to replace the file).
        force = bool(data.get("force"))
        target = self.server.shared_dir / name
        problem = self.server.relpath_problem(name)
        if problem:
            self.send_json(
                HTTPStatus.BAD_REQUEST, {"status": "error", "message": problem}
            )
            return
        if not force and target.is_file() and last_modified is not None:
            try:
                stat = target.stat()
            except OSError:
                stat = None
            if (
                stat is not None
                and stat.st_size == size
                and abs(stat.st_mtime - last_modified / 1000) <= 1.5
            ):
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "status": "success",
                        "exists": True,
                        "name": name,
                        "size": size,
                    },
                )
                return

        window = self.server.upload_active_window
        conflict: UploadSession | None = None
        with self.server._init_lock:
            requested = str(data.get("sessionId") or "").strip()
            session = None
            if is_valid_session_id(requested):
                session = self.server.get_session(requested)
                if session is not None and session.owner_id not in (None, self.current_user()["id"]):
                    self.send_json(HTTPStatus.FORBIDDEN, {"status": "error", "message": "无权访问上传会话"})
                    return
                if session is not None and session.owner_id is None and session.name == name and session.size == size:
                    session.owner_id = self.current_user()["id"]
                    session.save_meta()
                if session is not None and (session.name != name or session.size != size):
                    # Stale session for a different payload - start over.
                    session.discard()
                    self.server.drop_session(session.id)
                    session = None

            # 续接：客户端没带 sessionId（换标签页 / 清了 localStorage / 换设备）
            # 或带的 id 服务端已不认识时，按「同文件指纹」(name + size +
            # lastModified) 找未完成会话复用，而不是静默清零新开。
            # 客户端显式 "fresh": true 时才放弃旧进度新开。
            fresh = bool(data.get("fresh"))
            resumed_by = "sessionId" if session is not None else None
            if fresh and session is not None:
                session.discard()
                self.server.drop_session(session.id)
                session = None
                resumed_by = None
            if session is None:
                match = self.server.find_session_by_fingerprint(
                    name, size, last_modified, self.current_user()["id"]
                )
                if match is not None:
                    active = match.is_active(window)
                    if fresh:
                        # 显式新开。活跃会话属于另一个正在写的客户端，不去
                        # 删它（否则对方写到一半 404）；只是另开新会话。
                        if not active:
                            match.discard()
                            self.server.drop_session(match.id)
                    elif active:
                        # F3：另一个客户端正在写同一文件，且本请求没带该会话
                        # 的 sessionId -> 409，禁止双写。
                        conflict = match
                    else:
                        session = match
                        resumed_by = "fingerprint"

            if session is None and conflict is None:
                session_id = (
                    requested
                    if is_valid_session_id(requested) and not fresh
                    else uuid.uuid4().hex
                )
                session = UploadSession(
                    session_id, name, size, last_modified, self.server.uploads_dir, self.current_user()["id"]
                )
                session.discard()
                session.part.touch()
                session.save_meta()
                self.server.put_session(session)
            elif (
                conflict is None
                and session.last_modified is None
                and last_modified is not None
            ):
                session.last_modified = last_modified
                session.save_meta()
            if conflict is None:
                session.mark_active()

        if conflict is not None:
            ago = conflict.active_ago() or 0.0
            self.send_json(
                HTTPStatus.CONFLICT,
                {
                    "status": "error",
                    "conflict": True,
                    "message": "同文件已在上传（另一个页面或设备正在写入），请稍后再试",
                    "sessionId": conflict.id,
                    "name": conflict.name,
                    "size": conflict.size,
                    "offset": conflict.offset,
                    "resumed": False,
                    "resumedBy": None,
                    "chunkSize": self.server.upload_chunk_size,
                    "maxChunkSize": MAX_UPLOAD_CHUNK,
                    "exists": False,
                    "activeAgoMs": int(ago * 1000),
                    "activeWindowMs": int(window * 1000),
                    "retryAfterMs": max(0, int((window - ago) * 1000)),
                },
            )
            return

        free = free_space(self.server.uploads_dir)
        needed = size - session.offset
        if 0 <= free < needed:
            self.send_json(
                HTTPStatus.INSUFFICIENT_STORAGE,
                {
                    "status": "error",
                    "message": (
                        f"磁盘空间不足：剩余 {format_size(free)}，"
                        f"本次还需 {format_size(needed)}"
                    ),
                },
            )
            return

        self.send_json(
            HTTPStatus.OK,
            {
                "status": "success",
                "sessionId": session.id,
                "name": name,
                "size": size,
                "offset": session.offset,
                # resumed: 是否复用了已有会话；resumedBy: "sessionId" |
                # "fingerprint" | null（新开）
                "resumed": resumed_by is not None,
                "resumedBy": resumed_by,
                "chunkSize": self.server.upload_chunk_size,
                "maxChunkSize": MAX_UPLOAD_CHUNK,
                "exists": False,
            },
        )

    @filesystem_operation
    def handle_upload_chunk(self, query: dict[str, list[str]]) -> None:
        """Append one chunk.

        Headers: X-Upload-Offset (start byte), X-Chunk-CRC32 (optional hex).
        Resending an already-stored range is a no-op, which is what makes
        blind retries after a dropped connection safe.
        """
        session = self._session_from_query(query)
        if session is None:
            return

        # NOTE: every early return below must drain the (possibly large) chunk
        # body, otherwise the peer sees a reset connection instead of the error.
        try:
            offset = int(self.headers.get("X-Upload-Offset", ""))
        except ValueError:
            self.fail(HTTPStatus.BAD_REQUEST, "缺少有效的 X-Upload-Offset",
                      MAX_UPLOAD_CHUNK)
            return

        length = self.content_length()
        if length is None:
            return
        if length > MAX_UPLOAD_CHUNK:
            self.fail(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"分片超过上限 {format_size(MAX_UPLOAD_CHUNK)}",
                MAX_UPLOAD_CHUNK,
            )
            return
        if offset < 0 or offset + length > session.size:
            self.fail(
                HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                "分片偏移量越界",
                MAX_UPLOAD_CHUNK,
            )
            return

        expected_crc = (self.headers.get("X-Chunk-CRC32") or "").strip()

        with session.lock:
            current = session.offset
            if offset > current:
                self.send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "status": "error",
                        "message": "分片不连续，请从服务端偏移量续传",
                        "offset": current,
                    },
                )
                return
            crc = 0
            try:
                with session.part.open("r+b") as file:
                    file.seek(offset)
                    remaining = length
                    while remaining > 0:
                        piece = self.read_body(min(RECV_CHUNK, remaining))
                        if not piece:
                            self.fail(HTTPStatus.BAD_REQUEST, "分片数据读取中断")
                            return
                        crc = zlib.crc32(piece, crc)
                        file.write(piece)
                        remaining -= len(piece)
                    if offset + length < current:
                        file.truncate(offset + length)
                    file.flush()
            except OSError as exc:
                self.send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "message": f"写入分片失败：{exc}"},
                )
                return

        session.mark_active()
        # Keep the sidecar's mtime fresh so the periodic sweeper's TTL means
        # "abandoned for 7 days", not "created 7 days ago".
        try:
            session.meta.touch()
        except OSError:
            pass

        if expected_crc:
            try:
                if int(expected_crc, 16) != (crc & 0xFFFFFFFF):
                    with session.lock:
                        with session.part.open("r+b") as file:
                            file.truncate(offset)
                    self.send_json(
                        HTTPStatus.CONFLICT,
                        {
                            "status": "error",
                            "message": "分片校验失败，已丢弃该分片",
                            "offset": offset,
                        },
                    )
                    return
            except ValueError:
                pass  # malformed CRC header -> skip the integrity check

        self.send_json(
            HTTPStatus.OK,
            {
                "status": "success",
                "offset": offset + length,
                "size": session.size,
                "received": length,
            },
        )

    def handle_upload_status(self, query: dict[str, list[str]]) -> None:
        """Report how many bytes of a session are already stored."""
        session = self._session_from_query(query)
        if session is None:
            return
        offset = session.offset
        self.send_json(
            HTTPStatus.OK,
            {
                "status": "success",
                "sessionId": session.id,
                "name": session.name,
                "size": session.size,
                "offset": offset,
                "complete": offset >= session.size,
            },
        )

    @filesystem_operation
    def handle_upload_complete(self, query: dict[str, list[str]]) -> None:
        """Finalise a session: verify size, then atomically publish the file."""
        session = self._session_from_query(query)
        if session is None:
            return
        with session.lock:
            offset = session.offset
            if offset != session.size:
                self.send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "status": "error",
                        "message": (
                            f"文件不完整：已接收 {format_size(offset)} / "
                            f"{format_size(session.size)}"
                        ),
                        "offset": offset,
                    },
                )
                return
            target = self.server.shared_dir / session.name
            problem = self.server.relpath_problem(session.name)
            if problem:
                self.send_json(
                    HTTPStatus.CONFLICT, {"status": "error", "message": problem}
                )
                return
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(session.part, target)
            except OSError as exc:
                self.send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"status": "error", "message": f"保存文件失败：{exc}"},
                )
                return
            # Preserve the sender's original timestamp so a re-upload of the
            # same file can be detected and skipped instantly.
            if session.last_modified:
                try:
                    stamp = session.last_modified / 1000
                    os.utime(target, (stamp, stamp))
                except OSError:
                    pass
            session.meta.unlink(missing_ok=True)
            # 记录传输顺序：这次传输刚发生，文件排到列表末尾
            assign_file_order(self.server.shared_dir, session.name)
            try:
                size = target.stat().st_size
            except OSError:
                size = offset
        self.server.drop_session(session.id)
        self.send_json(
            HTTPStatus.OK,
            {
                "status": "success",
                "message": "文件上传成功",
                "name": session.name,
                "size": size,
            },
        )

    @filesystem_operation
    def handle_upload_abort(self, query: dict[str, list[str]]) -> None:
        """Throw away a session and its partial data."""
        session_id = (query.get("sessionId") or [""])[0].strip()
        if not is_valid_session_id(session_id):
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": "上传会话 ID 无效"},
            )
            return
        session = self.server.get_session(session_id)
        if session is not None:
            session = self._session_from_query(query)
            if session is None:
                return
            with session.lock:
                session.discard()
                self.server.drop_session(session_id)
        self.send_json(HTTPStatus.OK, {"status": "success", "message": "上传已取消"})

    @filesystem_operation
    def handle_upload(self, query: dict[str, list[str]]) -> None:
        """Legacy single-request upload (kept for old clients / scripts).

        Only for small files: bodies over LEGACY_UPLOAD_MAX are refused with
        413 and pointed at the resumable chunked API.
        """
        try:
            content_length = int(self.headers.get("Content-Length", ""))
            if content_length < 0:
                raise ValueError
        except ValueError:
            self.fail(HTTPStatus.LENGTH_REQUIRED, "缺少有效的 Content-Length")
            return

        if content_length > LEGACY_UPLOAD_MAX:
            self.fail(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"整包上传 /upload 仅支持不超过 {format_size(LEGACY_UPLOAD_MAX)} 的小文件"
                f"（本次请求超过 {format_size(LEGACY_UPLOAD_MAX)}，"
                f"共 {content_length} 字节），请使用分片上传 API："
                "POST /api/upload/init → /api/upload/chunk → /api/upload/complete"
                "（网页上传已自动分片）",
                LEGACY_UPLOAD_DRAIN_MAX,
            )
            return

        raw_name = query.get("filename", [""])[0]
        try:
            name = self.checked_name(raw_name, write=True)
        except ValueError as exc:
            self.fail(HTTPStatus.BAD_REQUEST, str(exc), LEGACY_UPLOAD_MAX)
            return

        limit = self.server.max_upload_size
        if limit is not None and content_length > limit:
            self.fail(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"文件超过服务端上限 {format_size(limit)}",
                LEGACY_UPLOAD_MAX,
            )
            return

        target = self.server.shared_dir / name
        temporary = self.server.uploads_dir / f"{uuid.uuid4().hex}.part"
        remaining = content_length
        try:
            with temporary.open("wb") as file:
                while remaining:
                    chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ConnectionError("上传连接提前断开")
                    file.write(chunk)
                    remaining -= len(chunk)
            os.replace(temporary, target)
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "message": str(exc)},
            )
            return

        self.send_json(
            HTTPStatus.OK,
            {"status": "success", "message": "文件上传成功", "name": name},
        )

    @filesystem_operation
    def handle_delete(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 64 * 1024:
                raise ValueError("请求内容长度无效")
            data = json.loads(self.read_body(content_length).decode("utf-8"))
            name = self.checked_name(str(data.get("filename", "")), write=True)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.fail(HTTPStatus.BAD_REQUEST, str(exc))
            return

        path = self.server.shared_dir / name
        if not path.is_file():
            self.send_json(
                HTTPStatus.NOT_FOUND,
                {"status": "error", "message": "文件不存在"},
            )
            return
        try:
            path.unlink()
        except OSError as exc:
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "message": str(exc)},
            )
            return
        drop_file_order(self.server.shared_dir, name)
        # F5：删掉子目录里最后一个文件后，顺手清理空目录（不碰共享根目录）
        self.send_json(HTTPStatus.OK, {"status": "success", "message": "文件已删除"})

    def handle_clipboard_delete(self, query: dict[str, list[str]]) -> None:
        entry_id = (query.get("id") or [""])[0]
        if entry_id:
            if clipboard_remove(self.server.shared_dir, entry_id):
                self.send_json(HTTPStatus.OK, {"status": "success", "message": "已删除该条"})
            else:
                self.send_json(
                    HTTPStatus.NOT_FOUND,
                    {"status": "error", "message": "该条记录已不存在"},
                )
            return
        clipboard_clear(self.server.shared_dir)
        self.send_json(HTTPStatus.OK, {"status": "success", "message": "历史记录已清空"})

    def handle_clipboard_get(self) -> None:
        """Latest-first history with ETag, so the 3s poll costs ~200 bytes."""
        items, seq = _read_clipboard(self.server.shared_dir)
        payload = json.dumps(
            {
                "items": items,
                "seq": seq,
                # text / updated 保留给旧版前端：等价于「最新一条」
                "text": items[0]["text"] if items else "",
                "updated": items[0]["time"] if items else None,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        etag = f'"clip-{zlib.crc32(payload):08x}-{len(payload)}"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(HTTPStatus.NOT_MODIFIED)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return
        self.send_bytes(
            HTTPStatus.OK,
            payload,
            "application/json; charset=utf-8",
            {"ETag": etag},
            cache_control="no-cache",
        )

    # -- ① presence ------------------------------------------------------
    def _presence_payload(self, self_entry: dict | None, self_id: str | None) -> dict:
        peers = self.server.presence_peers(self_id)
        body: dict = {
            "peers": peers,
            "count": len(peers),
            "ttl": int(self.server.presence_ttl),
            "serverTime": int(time.time() * 1000),
        }
        if self_entry is not None:
            body["self"] = {
                "id": self_entry["id"],
                "nickname": self_entry["nickname"],
                "lastSeen": int(self_entry["lastSeen"] * 1000),
            }
        return body

    def handle_presence_get(self, params: dict[str, list[str]]) -> None:
        self_id = (params.get("id") or [""])[0] or None
        self.send_json(
            HTTPStatus.OK,
            self._presence_payload(None, self_id),
            {"Cache-Control": "no-store"},
        )

    def handle_presence_post(self, require_existing_id: bool = False) -> None:
        """POST：心跳/登记/改名（可带 leave:true 主动下线）；PATCH：改名，须带 id。"""
        data = self.read_json_body(limit=4096)
        if data is None:
            return
        raw_id = data.get("id")
        client_id = raw_id if isinstance(raw_id, str) and PRESENCE_ID_RE.match(raw_id) else None
        if raw_id not in (None, "") and client_id is None:
            self.fail(HTTPStatus.BAD_REQUEST, "设备 id 格式无效")
            return
        if require_existing_id and client_id is None:
            self.fail(HTTPStatus.BAD_REQUEST, "缺少设备 id")
            return
        auth_token = self._session_token_from_cookie() if self.server.access_pin else None
        if self.is_guest() and client_id is not None:
            bound = self.server.presence_owner_token(client_id)
            if bound is not None and bound != auth_token:
                self.send_json(
                    HTTPStatus.FORBIDDEN,
                    {"status": "error", "message": "访客只能修改本机在线信息", "code": "guest_readonly"},
                )
                return
        if data.get("leave") is True:
            if client_id:
                self.server.presence_leave(client_id)
            self.send_json(HTTPStatus.OK, self._presence_payload(None, None))
            return
        nickname: str | None = None
        if "nickname" in data and data.get("nickname") is not None:
            nickname = sanitize_nickname(data.get("nickname"))
            if not nickname:
                self.fail(HTTPStatus.BAD_REQUEST, "昵称不能为空（1–16 个字符）")
                return
        elif require_existing_id:
            self.fail(HTTPStatus.BAD_REQUEST, "缺少昵称")
            return
        if client_id is None:
            client_id = uuid.uuid4().hex
        entry = self.server.presence_touch(
            client_id, nickname, self.headers.get("User-Agent") or "", auth_token
        )
        self.send_json(
            HTTPStatus.OK,
            self._presence_payload(entry, client_id),
            {"Cache-Control": "no-store"},
        )

    def handle_clipboard_post(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 256 * 1024:
                raise ValueError("请求体长度无效")
            data = json.loads(self.read_body(content_length).decode("utf-8"))
            text = str(data.get("text", ""))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.fail(HTTPStatus.BAD_REQUEST, str(exc))
            return
        if not text.strip():
            self.fail(HTTPStatus.BAD_REQUEST, "内容为空，请先输入要发送的文本")
            return
        if len(text) > CLIPBOARD_MAX_CHARS:
            self.fail(
                HTTPStatus.BAD_REQUEST,
                f"单条内容上限 {CLIPBOARD_MAX_CHARS} 字符，当前 {len(text)} 字符",
            )
            return
        entry = clipboard_add(self.server.shared_dir, text, self.client_address[0])
        self.send_json(
            HTTPStatus.OK,
            {"status": "success", "message": "已同步到剪贴板", "entry": entry},
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="局域网文件传输服务")
    parser.add_argument("--host", type=validate_ipv4, help="监听 IPv4 地址")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="监听端口；缺省时自动在 8080/8866/9000/9527/18080/8000 中选第一个可用端口",
    )
    parser.add_argument(
        "--shared-dir",
        type=Path,
        default=None,
        help="共享目录；缺省：源码旁 shared，或打包 exe 旁 shared",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="未指定 --host 时不询问，直接监听 0.0.0.0",
    )
    parser.add_argument(
        "--chunk-size",
        type=float,
        default=float(DEFAULT_UPLOAD_CHUNK) / (1024 * 1024),
        help=f"分片上传的建议分片大小（MB），默认 {DEFAULT_UPLOAD_CHUNK // (1024 * 1024)}",
    )
    parser.add_argument(
        "--max-upload-size",
        type=float,
        default=None,
        help="单个文件大小上限（GB）；缺省为不限制，仅受磁盘剩余空间约束",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="服务启动成功后自动打开局域网访问页面",
    )
    parser.add_argument(
        "--pin",
        type=str,
        default=None,
        help="可选访问口令；也可用环境变量 LAN_TRANSFER_PIN。未设置则不要求口令",
    )
    parser.add_argument(
        "--guest-pin",
        type=str,
        default=None,
        help="可选只读访客口令（可下载/预览/看剪贴板，不能上传/删除/写剪贴板）；"
        "也可用环境变量 LAN_TRANSFER_GUEST_PIN。必须同时设置 --pin；与 --pin 相同则按主人处理",
    )
    parser.add_argument(
        "--ttl-days",
        type=int,
        default=None,
        help="共享文件自动过期天数（按入库时间删除；默认关）。"
        "也可用环境变量 LAN_TRANSFER_TTL_DAYS。"
        f"取值 0=关，1–{FILE_TTL_MAX_DAYS}；与上传分片 7 天清理无关",
    )
    args = parser.parse_args()
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("端口必须在 1 到 65535 之间")

    chunk_bytes = int(args.chunk_size * 1024 * 1024)
    if not MIN_UPLOAD_CHUNK <= chunk_bytes <= MAX_UPLOAD_CHUNK:
        parser.error(
            f"分片大小必须在 {MIN_UPLOAD_CHUNK // 1024} KB 到 "
            f"{MAX_UPLOAD_CHUNK // (1024 * 1024)} MB 之间"
        )
    args.chunk_size = chunk_bytes

    if args.max_upload_size is not None:
        if args.max_upload_size <= 0:
            parser.error("文件大小上限必须大于 0")
        args.max_upload_size = int(args.max_upload_size * 1024 ** 3)

    pin = args.pin if args.pin is not None else os.environ.get("LAN_TRANSFER_PIN")
    if pin is not None:
        pin = str(pin).strip()
    args.pin = pin or None

    guest_pin = (
        args.guest_pin if args.guest_pin is not None
        else os.environ.get("LAN_TRANSFER_GUEST_PIN")
    )
    if guest_pin is not None:
        guest_pin = str(guest_pin).strip()
    args.guest_pin = guest_pin or None
    if args.pin or args.guest_pin:
        print("提示：--pin 和 --guest-pin 已停用，请使用个人账号登录。")
    args.pin = None
    args.guest_pin = None

    if args.ttl_days is None:
        env_ttl = os.environ.get("LAN_TRANSFER_TTL_DAYS", "").strip()
        if env_ttl:
            try:
                args.ttl_days = int(env_ttl)
            except ValueError:
                parser.error("LAN_TRANSFER_TTL_DAYS 必须是整数天数")
        else:
            args.ttl_days = 0
    if args.ttl_days < 0:
        parser.error("--ttl-days / LAN_TRANSFER_TTL_DAYS 不能为负数")
    if args.ttl_days > FILE_TTL_MAX_DAYS:
        parser.error(
            f"--ttl-days / LAN_TRANSFER_TTL_DAYS 过大（上限 {FILE_TTL_MAX_DAYS} 天）"
        )

    if args.shared_dir is None:
        args.shared_dir = default_shared_dir()

    # Frozen onefile defaults align with run.bat; source launch defaults stay unchanged.
    if _is_frozen():
        if "--no-prompt" not in sys.argv:
            args.no_prompt = True
        if "--open-browser" not in sys.argv:
            args.open_browser = True

    return args


def choose_host(args: argparse.Namespace) -> str:
    if args.host:
        return args.host
    if args.no_prompt or not sys.stdin.isatty():
        return "0.0.0.0"

    detected = detect_lan_ip()
    print(f"检测到本机局域网 IP：{detected}")
    print("输入要监听的 IP；直接回车使用 0.0.0.0（所有本机 IPv4 网卡）。")
    while True:
        value = input("监听 IP [0.0.0.0]：").strip() or "0.0.0.0"
        try:
            return validate_ipv4(value)
        except argparse.ArgumentTypeError as exc:
            print(exc)


def main() -> int:
    args = parse_args()
    host = choose_host(args)
    shared_dir = args.shared_dir.expanduser().resolve()
    shared_dir.mkdir(parents=True, exist_ok=True)

    # Housekeeping: drop legacy temp files, then sweep abandoned sessions.
    for path in shared_dir.iterdir():
        if path.is_file() and is_upload_temporary(path):
            path.unlink(missing_ok=True)
    swept = sweep_upload_sessions(uploads_dir(shared_dir))
    if swept:
        print(
            f"已清理 {len(swept)} 个超过 "
            f"{UPLOAD_SESSION_TTL // 86400} 天未完成的上传。"
        )

    advertised_ip = detect_lan_ip() if host == "0.0.0.0" else host

    port = resolve_port(host, args.port)
    if port is None:
        if args.port is not None:
            print(
                f"启动失败：指定端口 {args.port} 不可用，请更换端口"
                "（例如 --port 8866）后重试。",
                file=sys.stderr,
            )
        else:
            print(
                "启动失败：所有候选端口均不可用，请用 --port 显式指定一个端口。",
                file=sys.stderr,
            )
        return 1
    if args.port is None and port != FALLBACK_PORTS[0]:
        print(f"提示：默认端口 {FALLBACK_PORTS[0]} 不可用，已自动切换到 {port}。")

    try:
        server = LanFileServer(
            (host, port),
            RequestHandler,
            shared_dir,
            advertised_ip,
            upload_chunk_size=args.chunk_size,
            max_upload_size=args.max_upload_size,
            access_pin=args.pin,
            guest_pin=args.guest_pin,
            file_ttl_days=args.ttl_days,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"启动失败：账号数据无效（{exc}）", file=sys.stderr)
        return 1
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        if code in {errno.EADDRINUSE, 10048}:
            print(f"启动失败：{host}:{port} 已被其他程序占用。", file=sys.stderr)
        elif code in {errno.EACCES, 10013}:
            print(
                f"启动失败：{host}:{port} 位于 Windows 保留端口段"
                "（Hyper-V/WSL 等预留）。请换一个端口，或以管理员身份运行\n"
                "  netsh int ipv4 add excludedportrange protocol=tcp startport=0 numberofports=0\n"
                "  后重启电脑以重置保留段。",
                file=sys.stderr,
            )
        elif code in {errno.EADDRNOTAVAIL, 10049}:
            print(f"启动失败：本机不存在 IP 地址 {host}。", file=sys.stderr)
        else:
            print(f"启动失败：无法监听 {host}:{port}（{exc}）", file=sys.stderr)
        return 1

    print("\n" + "=" * 58)
    print("局域网文件传输服务已启动")
    print(f"本机访问：http://127.0.0.1:{server.server_port}")
    print(f"局域网访问：http://{advertised_ip}:{server.server_port}")
    print(f"监听地址：{host}:{server.server_port}")
    print(f"共享目录：{shared_dir}")
    if args.pin:
        print("访问口令：已启用（浏览器需输入口令后才能传文件 / 看列表）")
    if args.guest_pin:
        print("访客口令：已启用（访客只读：可下载/预览/看剪贴板，不能上传/删除/写剪贴板）")
    if server.file_ttl_days > 0:
        print(f"共享文件保留 {server.file_ttl_days} 天（按入库时间自动删除）")
        try:
            expired = sweep_expired_shared_files(shared_dir, server.file_ttl_days)
        except OSError:
            expired = []
        if expired:
            print(f"已按 TTL 清理 {len(expired)} 个文件")
    resumed = len(server.upload_sessions)
    if resumed:
        print(f"未完成上传：{resumed} 个（重新选择同一文件即可续传）")
    print(
        f"分片大小：{format_size(server.upload_chunk_size)} · "
        f"单文件上限："
        f"{format_size(args.max_upload_size) if args.max_upload_size else '不限制'} · "
        f"剩余空间：{format_size(max(0, free_space(shared_dir)))}"
    )
    print("按 Ctrl+C 停止服务")
    print("=" * 58 + "\n")

    if args.open_browser:
        url = f"http://{advertised_ip}:{server.server_port}"
        timer = threading.Timer(0.5, webbrowser.open, args=(url, 2))
        timer.daemon = True
        timer.start()

    start_session_sweeper(server)
    start_file_ttl_sweeper(server)

    # 收到终止信号时在独立线程里 shutdown，避免与主线程 serve_forever 死锁
    def request_shutdown(signum: int, frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    try:
        signal.signal(signal.SIGTERM, request_shutdown)
    except (ValueError, OSError):
        pass  # 非主线程或平台不支持时忽略

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止服务……")
    finally:
        server.server_close()
        print(f"服务已停止，端口 {server.server_port} 已释放。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
