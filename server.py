#!/usr/bin/env python3
"""A small, dependency-free LAN file transfer server."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import mimetypes
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
import webbrowser
from collections.abc import Callable
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit


# PyInstaller's windowed mode sets standard streams to None. Redirect them so
# status messages never crash the background server.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")


SOURCE_DIR = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", SOURCE_DIR))
else:
    BASE_DIR = SOURCE_DIR
    BUNDLE_DIR = SOURCE_DIR
INDEX_FILE = BUNDLE_DIR / "index.html"
CHUNK_SIZE = 1024 * 1024
DEFAULT_PORT = 8080
PORT_SEARCH_COUNT = 100


class ManagedBrowserWindow:
    """Open a dedicated browser window that can be closed with the server."""

    def __init__(self, on_window_closed: Callable[[], None] | None = None) -> None:
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._profile_dir: Path | None = None
        self._closed = False
        self._on_window_closed = on_window_closed

    @staticmethod
    def _find_browser() -> Path | None:
        candidates: list[Path] = []
        if os.name == "nt":
            locations = (
                ("PROGRAMFILES(X86)", "Microsoft/Edge/Application/msedge.exe"),
                ("PROGRAMFILES", "Microsoft/Edge/Application/msedge.exe"),
                ("LOCALAPPDATA", "Microsoft/Edge/Application/msedge.exe"),
                ("PROGRAMFILES", "Google/Chrome/Application/chrome.exe"),
                ("PROGRAMFILES(X86)", "Google/Chrome/Application/chrome.exe"),
            )
            for variable, relative_path in locations:
                root = os.environ.get(variable)
                if root:
                    candidates.append(Path(root) / relative_path)
        else:
            for command in ("google-chrome", "chromium", "microsoft-edge"):
                executable = shutil.which(command)
                if executable:
                    candidates.append(Path(executable))
        return next((path for path in candidates if path.is_file()), None)

    def open(self, url: str) -> None:
        browser = self._find_browser()
        if browser is None:
            webbrowser.open(url, new=2)
            print("提示：未找到可管理的浏览器，网页需要手动关闭。")
            return

        profile_dir = Path(tempfile.mkdtemp(prefix="lan-transfer-browser-"))
        command = [
            str(browser),
            f"--app={url}",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-mode",
            "--disable-features=msEdgeFirstRunExperience",
        ]
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            shutil.rmtree(profile_dir, ignore_errors=True)
            webbrowser.open(url, new=2)
            print("提示：独立网页窗口启动失败，网页需要手动关闭。")
            return

        with self._lock:
            if self._closed:
                process.terminate()
                shutil.rmtree(profile_dir, ignore_errors=True)
                return
            self._process = process
            self._profile_dir = profile_dir
        watcher = threading.Thread(
            target=self._watch_process,
            args=(process,),
            name="browser-window-watcher",
            daemon=True,
        )
        watcher.start()
        print("已打开独立网页窗口；停止服务时会自动关闭。")

    def _watch_process(self, process: subprocess.Popen[bytes]) -> None:
        process.wait()
        with self._lock:
            should_stop_server = not self._closed and process is self._process
            on_window_closed = self._on_window_closed
        if should_stop_server and on_window_closed is not None:
            print("网页窗口已关闭，正在停止后台服务……")
            on_window_closed()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            process = self._process
            profile_dir = self._profile_dir
            self._process = None
            self._profile_dir = None

        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if profile_dir is not None:
            shutil.rmtree(profile_dir, ignore_errors=True)


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
    return name


def is_upload_temporary(path: Path) -> bool:
    """Identify temporary files created by this server during an upload."""
    parts = path.name.rsplit(".", 2)
    if len(parts) != 3 or parts[2] != "part":
        return False
    token = parts[1]
    return len(token) == 32 and all(char in "0123456789abcdef" for char in token)


def is_address_in_use(error: OSError) -> bool:
    """Return whether a bind failure means that another process owns the port."""
    return (
        error.errno in {errno.EADDRINUSE, 10048}
        or getattr(error, "winerror", None) == 10048
    )


class LanFileServer(ThreadingHTTPServer):
    daemon_threads = True
    # SO_REUSEADDR can allow two processes to bind the same address on Windows.
    # Keep it on Unix for quick restarts, but require an exclusive port on Windows.
    allow_reuse_address = os.name != "nt"

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        shared_dir: Path,
        advertised_ip: str,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.shared_dir = shared_dir
        self.advertised_ip = advertised_ip


class RequestHandler(BaseHTTPRequestHandler):
    server: LanFileServer

    def log_message(self, format: str, *args: object) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{stamp}] {self.client_address[0]} - {format % args}")

    def send_bytes(
        self,
        status: int,
        content: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status: int, data: object) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_bytes(status, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path in {"/", "/index.html"}:
            if not INDEX_FILE.is_file():
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "index.html 不存在")
                return
            self.send_bytes(
                HTTPStatus.OK,
                INDEX_FILE.read_bytes(),
                "text/html; charset=utf-8",
            )
            return

        if parsed.path == "/api/ip":
            self.send_json(
                HTTPStatus.OK,
                {
                    "ip": self.server.advertised_ip,
                    "port": self.server.server_port,
                    "url": f"http://{self.server.advertised_ip}:{self.server.server_port}",
                },
            )
            return

        if parsed.path == "/api/files":
            self.handle_file_list()
            return

        if parsed.path.startswith("/download/"):
            self.handle_download(parsed.path[len("/download/") :])
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/upload":
            self.handle_upload(parse_qs(parsed.query))
            return
        if parsed.path == "/delete":
            self.handle_delete()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def handle_file_list(self) -> None:
        files = []
        try:
            paths = sorted(
                (
                    path
                    for path in self.server.shared_dir.iterdir()
                    if path.is_file() and not is_upload_temporary(path)
                ),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            for path in paths:
                stat = path.stat()
                files.append(
                    {
                        "name": path.name,
                        "size": stat.st_size,
                        "date": datetime.fromtimestamp(stat.st_mtime).strftime(
                            "%Y-%m-%d %H:%M"
                        ),
                    }
                )
        except OSError as exc:
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"status": "error", "message": str(exc)},
            )
            return
        self.send_json(HTTPStatus.OK, files)

    def handle_download(self, raw_name: str) -> None:
        try:
            name = safe_filename(raw_name)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})
            return

        path = self.server.shared_dir / name
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        ascii_fallback = "download" + Path(name).suffix
        disposition = (
            f'attachment; filename="{ascii_fallback}"; '
            f"filename*=UTF-8''{quote(name, safe='')}"
        )
        try:
            size = path.stat().st_size
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", disposition)
            self.end_headers()
            with path.open("rb") as file:
                while chunk := file.read(CHUNK_SIZE):
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_upload(self, query: dict[str, list[str]]) -> None:
        raw_name = query.get("filename", [""])[0]
        try:
            name = safe_filename(raw_name)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"status": "error", "message": str(exc)})
            return

        try:
            content_length = int(self.headers.get("Content-Length", ""))
            if content_length < 0:
                raise ValueError
        except ValueError:
            self.send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"status": "error", "message": "缺少有效的 Content-Length"},
            )
            return

        target = self.server.shared_dir / name
        temporary = self.server.shared_dir / f".{name}.{uuid.uuid4().hex}.part"
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

    def handle_delete(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 64 * 1024:
                raise ValueError("请求内容长度无效")
            data = json.loads(self.rfile.read(content_length).decode("utf-8"))
            name = safe_filename(str(data.get("filename", "")))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"status": "error", "message": str(exc)},
            )
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
        self.send_json(HTTPStatus.OK, {"status": "success", "message": "文件已删除"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="局域网文件传输服务")
    parser.add_argument("--host", type=validate_ipv4, help="监听 IPv4 地址")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=(
            f"首选监听端口，默认 {DEFAULT_PORT}；被占用时自动尝试后续端口，"
            "设为 0 可由系统随机分配"
        ),
    )
    parser.add_argument(
        "--strict-port",
        action="store_true",
        help="端口被占用时直接退出，不自动尝试其他端口",
    )
    parser.add_argument(
        "--shared-dir",
        type=Path,
        default=BASE_DIR / "shared",
        help="共享目录，默认使用程序旁边的 shared 文件夹",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="未指定 --host 时不询问，直接监听 0.0.0.0",
    )
    parser.add_argument(
        "--open-browser",
        dest="open_browser",
        action="store_true",
        help="服务启动成功后自动打开局域网访问页面",
    )
    parser.add_argument(
        "--no-open-browser",
        dest="open_browser",
        action="store_false",
        help="不自动打开网页窗口（EXE 默认会自动打开）",
    )
    parser.set_defaults(open_browser=getattr(sys, "frozen", False))
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("端口必须在 0 到 65535 之间")
    return args


def create_server(
    host: str,
    preferred_port: int,
    strict_port: bool,
    shared_dir: Path,
    advertised_ip: str,
) -> LanFileServer:
    """Bind the preferred port, falling forward when it is already occupied."""
    if preferred_port == 0 or strict_port:
        candidate_ports = [preferred_port]
    else:
        last_port = min(65535, preferred_port + PORT_SEARCH_COUNT - 1)
        candidate_ports = range(preferred_port, last_port + 1)

    last_error: OSError | None = None
    for port in candidate_ports:
        try:
            return LanFileServer(
                (host, port), RequestHandler, shared_dir, advertised_ip
            )
        except OSError as exc:
            if not is_address_in_use(exc):
                raise
            last_error = exc

    if last_error is not None:
        raise last_error
    raise OSError("没有可尝试的端口")


def choose_host(args: argparse.Namespace) -> str:
    if args.host:
        return args.host
    if args.no_prompt or sys.stdin is None or not sys.stdin.isatty():
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
    for path in shared_dir.iterdir():
        if path.is_file() and is_upload_temporary(path):
            path.unlink(missing_ok=True)
    advertised_ip = detect_lan_ip() if host == "0.0.0.0" else host

    try:
        server = create_server(
            host,
            args.port,
            args.strict_port,
            shared_dir,
            advertised_ip,
        )
    except OSError as exc:
        if is_address_in_use(exc):
            if args.strict_port:
                message = f"启动失败：{host}:{args.port} 已被占用。"
            else:
                end_port = min(65535, args.port + PORT_SEARCH_COUNT - 1)
                message = f"启动失败：{args.port}–{end_port} 端口均被占用。"
            print(message, file=sys.stderr)
        else:
            print(f"启动失败：无法监听 {host}:{args.port}（{exc}）", file=sys.stderr)
        return 1

    if args.port != 0 and server.server_port != args.port:
        print(f"提示：端口 {args.port} 已被占用，已自动改用 {server.server_port}。")

    print("\n" + "=" * 58)
    print("局域网文件传输服务已启动")
    print(f"本机访问：http://127.0.0.1:{server.server_port}")
    print(f"局域网访问：http://{advertised_ip}:{server.server_port}")
    print(f"监听地址：{host}:{server.server_port}")
    print(f"共享目录：{shared_dir}")
    print("按 Ctrl+C 停止服务")
    print("=" * 58 + "\n")

    browser_window: ManagedBrowserWindow | None = None
    browser_timer: threading.Timer | None = None
    if args.open_browser:
        url = f"http://{advertised_ip}:{server.server_port}/?managed=1"
        browser_window = ManagedBrowserWindow(server.shutdown)
        browser_timer = threading.Timer(0.5, browser_window.open, args=(url,))
        browser_timer.daemon = True
        browser_timer.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止服务……")
    finally:
        server.server_close()
        if browser_timer is not None:
            browser_timer.cancel()
        if browser_window is not None:
            browser_window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
