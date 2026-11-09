# -*- coding: utf-8 -*-
"""IPA 上架助手：证书申请/合成、备案信息与 IPA 上传（App Store Connect API）。"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import plistlib
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings
import webbrowser
import zipfile
from datetime import datetime
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID
    CRYPTO_ERROR = ""
except Exception as exc:  # 缺依赖时仍可上传，只是证书助手不可用
    CRYPTO_ERROR = str(exc)

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from tkinter.scrolledtext import ScrolledText

APP_TITLE = "IPA 上架助手"
APP_ICON = "ipa.ico"
_DATA_ROOT = Path(os.environ.get("APPDATA") or Path.home())
APP_DIR = _DATA_ROOT / "IPAUploader"
# 兼容旧版本：新目录不存在时原地沿用旧目录，不移动用户已有数据
if not APP_DIR.exists() and (_DATA_ROOT / "BeimingIpaUploader").exists():
    APP_DIR = _DATA_ROOT / "BeimingIpaUploader"
CONFIG_PATH = APP_DIR / "config.json"
HISTORY_PATH = APP_DIR / "history.json"
LOG_DIR = APP_DIR / "logs"
KEYS_DIR = APP_DIR / "private_keys"
CERT_DIR = APP_DIR / "certs"
CERT_INDEX_PATH = APP_DIR / "certs.json"
PROFILE_DIR = CERT_DIR / "profiles"

CREATE_NO_WINDOW = 0x08000000

DEFAULT_CONFIG = {
    "app_apple_id": "",
    "api_key_id": "",
    "api_issuer": "",
    "api_key_type": "team",
    "api_key_path": "",
    "default_ipa_dir": str(Path.home() / "Downloads"),
}

COLOR_OK = "#1e7b34"
COLOR_ERR = "#c5221f"
COLOR_MUTED = "#5f6b7a"
COLOR_INFO = "#1a5fb4"
COLOR_HEADER = "#173a5e"


def app_icon_path() -> str:
    bases = []
    if getattr(sys, "_MEIPASS", ""):
        bases.append(Path(sys._MEIPASS))
    bases.append(Path(__file__).resolve().parent)
    for base in bases:
        candidate = base / APP_ICON
        if candidate.is_file():
            return str(candidate)
    return ""


# ---------------------------------------------------------------- 存储


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        if CONFIG_PATH.exists():
            data = json.loads(CONFIG_PATH.read_text("utf-8"))
            if isinstance(data, dict):
                cfg.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
    except Exception:
        pass
    return cfg


def save_config(cfg: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), "utf-8")


def load_history() -> list[dict]:
    try:
        if HISTORY_PATH.exists():
            data = json.loads(HISTORY_PATH.read_text("utf-8"))
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
    except Exception:
        pass
    return []


def save_history(items: list[dict]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(items, ensure_ascii=False, indent=2), "utf-8")


# ---------------------------------------------------------------- 工具函数


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024 or unit == "GB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} GB"


def human_duration(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds} 秒"
    return f"{seconds // 60} 分 {seconds % 60} 秒"


def decode_bytes(raw: bytes) -> str:
    for enc in ("utf-8", "gbk"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", "replace")
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text).strip()


def inspect_ipa(path: str) -> dict:
    info = {
        "path": path,
        "name": Path(path).name,
        "size": 0,
        "bundle_id": "",
        "version": "",
        "build": "",
        "error": "",
    }
    try:
        info["size"] = os.path.getsize(path)
        with zipfile.ZipFile(path) as archive:
            target = None
            for name in archive.namelist():
                if name.startswith("Payload/") and name.count("/") == 2 and name.endswith(".app/Info.plist"):
                    target = name
                    break
            if not target:
                raise ValueError("包内未找到 Payload/*.app/Info.plist")
            payload = plistlib.loads(archive.read(target))
        info["bundle_id"] = str(payload.get("CFBundleIdentifier", "") or "")
        info["version"] = str(payload.get("CFBundleShortVersionString", "") or "")
        info["build"] = str(payload.get("CFBundleVersion", "") or "")
    except Exception as exc:
        info["error"] = str(exc)
    return info


# ---------------------------------------------------------------- App Store Connect API
#
# Transporter 4.3 的 Windows 版不带 swinfo 分析器，无法生成 AppStoreInfo.plist，
# 因此直接调用官方 Build Upload 接口上传二进制包。


ASC_API_BASE = "https://api.appstoreconnect.apple.com"
JWT_LIFETIME = 900

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class UploadCanceled(Exception):
    pass


class AscApiError(RuntimeError):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _der_parse(data: bytes) -> tuple[int, bytes, int]:
    if len(data) < 2:
        raise AscApiError("私钥格式异常")
    tag, pos = data[0], 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    return tag, data[pos:pos + length], pos + length


def _der_children(body: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(body):
        tag, content, size = _der_parse(body[pos:])
        items.append((tag, content))
        pos += size
    return items


def _read_ec_private_key(key_path: str) -> int:
    text = Path(key_path).read_text("ascii")
    body = "".join(
        line for line in text.splitlines() if line and not line.startswith("-----")
    )
    der = base64.b64decode(body)
    tag, content, _ = _der_parse(der)
    if tag != 0x30:
        raise AscApiError(".p8 不是有效的 EC 私钥")
    children = _der_children(content)
    inner = children
    if len(children) >= 3 and children[0][0] == 0x02 and children[1][0] == 0x30:
        # PKCS#8：OCTET STRING 里再套一层 ECPrivateKey
        inner_tag, inner_body, _ = _der_parse(children[2][1])
        if inner_tag == 0x30:
            inner = _der_children(inner_body)
    if len(inner) < 2 or inner[1][0] != 0x04:
        raise AscApiError(".p8 不是有效的 EC 私钥")
    scalar = int.from_bytes(inner[1][1], "big")
    if not 0 < scalar < _P256_N:
        raise AscApiError(".p8 私钥内容无效")
    return scalar


def _ec_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (slope * slope - x1 - x2) % _P256_P
    return x3, (slope * (x1 - x3) - y1) % _P256_P


def _ec_mul(multiplier: int, point):
    result = None
    addend = point
    while multiplier:
        if multiplier & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        multiplier >>= 1
    return result


def _es256_sign(scalar: int, message: bytes) -> bytes:
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        nonce = secrets.randbelow(_P256_N - 1) + 1
        point = _ec_mul(nonce, _P256_G)
        r = point[0] % _P256_N
        if not r:
            continue
        s = pow(nonce, -1, _P256_N) * (digest + r * scalar) % _P256_N
        if not s:
            continue
        if s > _P256_N // 2:
            s = _P256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class AscToken:
    """按需生成 ES256 JWT，快过期时自动续签。"""

    def __init__(self, key_path: str, key_id: str, key_type: str, issuer: str):
        self.key_path = key_path
        self.key_id = key_id
        self.key_type = (key_type or "team").lower()
        self.issuer = issuer
        self._token = ""
        self._expires = 0.0
        self._scalar: int | None = None

    def value(self) -> str:
        if self._token and time.time() < self._expires - 120:
            return self._token
        if self._scalar is None:
            self._scalar = _read_ec_private_key(self.key_path)
        now = int(time.time())
        header = {"alg": "ES256", "kid": self.key_id, "typ": "JWT"}
        payload = {"iat": now, "exp": now + JWT_LIFETIME, "aud": "appstoreconnect-v1"}
        if self.key_type == "individual":
            payload["sub"] = "user"
        else:
            if not self.issuer:
                raise AscApiError("团队密钥缺少 Issuer ID")
            payload["iss"] = self.issuer
        signing_input = "{}.{}".format(
            _b64url(json.dumps(header, separators=(",", ":")).encode()),
            _b64url(json.dumps(payload, separators=(",", ":")).encode()),
        ).encode("ascii")
        signature = _es256_sign(self._scalar, signing_input)
        self._token = signing_input.decode("ascii") + "." + _b64url(signature)
        self._expires = float(now + JWT_LIFETIME)
        return self._token


def _api_error_detail(body) -> str:
    if not isinstance(body, dict):
        return ""
    parts = []
    for item in body.get("errors") or []:
        if isinstance(item, dict):
            text = " ".join(
                str(item.get(key) or "") for key in ("code", "title", "detail")
            ).strip()
            if text:
                parts.append(text)
    return "；".join(parts)


def api_request(method: str, path: str, token: str, payload: dict | None = None, timeout: float = 90) -> dict:
    data = None
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        path if path.startswith("http") else ASC_API_BASE + path,
        data=data, headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw)
        except Exception:
            body = None
        detail = _api_error_detail(body) or decode_bytes(raw)[:300]
        raise AscApiError(f"HTTP {exc.code}：{detail}") from None
    except urllib.error.URLError as exc:
        raise AscApiError(f"网络错误：{exc.reason}") from None
    return json.loads(raw) if raw else {}


def _put_chunk(operation: dict, handle, index: int, total: int) -> int:
    offset = int(operation.get("offset") or 0)
    length = int(operation.get("length") or 0)
    handle.seek(offset)
    chunk = handle.read(length)
    if len(chunk) != length:
        raise AscApiError(f"分片 {index}/{total} 读取失败（文件长度与预留不一致）")
    headers = {
        str(item.get("name")): str(item.get("value"))
        for item in operation.get("requestHeaders") or []
        if isinstance(item, dict) and item.get("name")
    }
    request = urllib.request.Request(
        operation["url"], data=chunk, headers=headers,
        method=operation.get("method") or "PUT",
    )
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        raise AscApiError(
            f"分片 {index}/{total} 上传失败：HTTP {exc.code} {decode_bytes(exc.read())[:200]}"
        ) from None
    except urllib.error.URLError as exc:
        raise AscApiError(f"分片 {index}/{total} 上传失败：{exc.reason}") from None
    return len(chunk)


def file_md5(path: str) -> str:
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _state_detail(item) -> str:
    if isinstance(item, dict):
        for key in ("description", "message", "detail", "code"):
            if item.get(key):
                return str(item[key])
        return json.dumps(item, ensure_ascii=False)
    return str(item)


def resolve_app_id(bundle_id: str, cfg: dict, token: "AscToken", emit) -> tuple[str, str, str]:
    """按 IPA 的 Bundle ID 查 App Store Connect 应用，返回 (数字 ID, Bundle ID, 应用名)。"""
    configured = str(cfg.get("app_apple_id") or "").strip()
    if bundle_id:
        query = urllib.parse.urlencode({"filter[bundleId]": bundle_id, "limit": "10"})
        apps = api_request("GET", f"/v1/apps?{query}", token.value()).get("data") or []
        exact = []
        for item in apps:
            attrs = item.get("attributes") or {}
            if str(attrs.get("bundleId") or "") == bundle_id:
                exact.append((str(item.get("id") or ""), bundle_id, str(attrs.get("name") or "")))
        if len(exact) > 1 and configured:
            preferred = [item for item in exact if item[0] == configured]
            exact = preferred or exact
        if len(exact) == 1:
            app_id, remote_bundle, name = exact[0]
            emit(f"已按 Bundle ID 识别应用：{name or app_id}（{remote_bundle} / {app_id}）")
            return app_id, remote_bundle, name
        if exact:
            raise AscApiError(
                "Bundle ID 匹配到多个应用（"
                + "、".join(item[0] for item in exact)
                + "），请在设置里填写 App 数字 ID"
            )
        raise AscApiError(f"App Store Connect 里没有 Bundle ID 为 {bundle_id} 的应用")
    if not configured.isdigit():
        raise AscApiError("无法从 IPA 读取 Bundle ID，请先在设置里填写 App 数字 ID")
    app = api_request("GET", f"/v1/apps/{configured}", token.value()).get("data") or {}
    attrs = app.get("attributes") or {}
    return configured, str(attrs.get("bundleId") or ""), str(attrs.get("name") or "")


def upload_build_via_api(
    ipa_path: str,
    info: dict,
    cfg: dict,
    key_path: str,
    emit,
    set_progress,
    cancel_check,
) -> dict:
    version = str(info.get("version") or "").strip()
    build = str(info.get("build") or "").strip()
    bundle_id = str(info.get("bundle_id") or "").strip()
    if not (version and build):
        raise AscApiError("无法从 IPA 中读取版本号和构建号")

    token = AscToken(
        key_path=key_path,
        key_id=str(cfg.get("api_key_id") or "").strip(),
        key_type=str(cfg.get("api_key_type") or "team"),
        issuer=str(cfg.get("api_issuer") or "").strip(),
    )

    emit("正在校验 API 凭据…")
    app_id, remote_bundle, app_name = resolve_app_id(bundle_id, cfg, token, emit)
    emit(f"应用已确认：{app_name or app_id} / {app_id} / {remote_bundle or '未知 Bundle ID'}")
    if bundle_id and remote_bundle and bundle_id != remote_bundle:
        raise AscApiError(f"Bundle ID 不匹配：IPA 是 {bundle_id}，App 数字 ID 对应 {remote_bundle}")

    if cancel_check():
        raise UploadCanceled()

    emit(f"创建 BuildUpload：{version} ({build}) / IOS")
    created = api_request(
        "POST", "/v1/buildUploads", token.value(),
        {
            "data": {
                "type": "buildUploads",
                "attributes": {
                    "cfBundleShortVersionString": version,
                    "cfBundleVersion": build,
                    "platform": "IOS",
                },
                "relationships": {"app": {"data": {"type": "apps", "id": app_id}}},
            }
        },
    )
    upload_id = str((created.get("data") or {}).get("id") or "")
    if not upload_id:
        raise AscApiError("创建 BuildUpload 失败：响应缺少 id")
    emit(f"BuildUpload 已创建：{upload_id}")

    size = os.path.getsize(ipa_path)
    file_name = Path(ipa_path).name
    emit(f"预留上传文件：{file_name}（{human_size(size)}）")
    reserved = api_request(
        "POST", "/v1/buildUploadFiles", token.value(),
        {
            "data": {
                "type": "buildUploadFiles",
                "attributes": {
                    "assetType": "ASSET",
                    "fileName": file_name,
                    "fileSize": size,
                    "uti": "com.apple.ipa",
                },
                "relationships": {
                    "buildUpload": {"data": {"type": "buildUploads", "id": upload_id}}
                },
            }
        },
    )
    file_data = reserved.get("data") or {}
    file_id = str(file_data.get("id") or "")
    operations = (file_data.get("attributes") or {}).get("uploadOperations") or []
    if not file_id or not operations:
        raise AscApiError("预留上传文件失败：响应缺少 uploadOperations")
    emit(f"开始上传，共 {len(operations)} 个分片")

    uploaded = 0
    with open(ipa_path, "rb") as handle:
        for index, operation in enumerate(operations, start=1):
            if cancel_check():
                raise UploadCanceled()
            uploaded += _put_chunk(operation, handle, index, len(operations))
            set_progress(uploaded / size * 100 if size else 100)
            emit(f"分片 {index}/{len(operations)} 完成（{human_size(uploaded)} / {human_size(size)}）")

    if cancel_check():
        raise UploadCanceled()

    checksum = file_md5(ipa_path)
    emit(f"提交校验（MD5 {checksum}）…")
    api_request(
        "PATCH", f"/v1/buildUploadFiles/{file_id}", token.value(),
        {
            "data": {
                "type": "buildUploadFiles",
                "id": file_id,
                "attributes": {
                    "uploaded": True,
                    "sourceFileChecksums": {
                        "file": {"hash": checksum, "algorithm": "MD5"}
                    },
                },
            }
        },
    )
    emit("提交成功，等待 Apple 处理构建…")
    set_progress(None)

    deadline = time.time() + 60 * 60
    last_state = ""
    while time.time() < deadline:
        for _ in range(15):
            if cancel_check():
                raise UploadCanceled()
            time.sleep(1)
        data = (api_request("GET", f"/v1/buildUploads/{upload_id}", token.value()).get("data") or {})
        state_object = (data.get("attributes") or {}).get("state") or {}
        state = str(state_object.get("state") or "")
        if state and state != last_state:
            emit(f"处理状态：{state}")
            last_state = state
        for item in state_object.get("errors") or []:
            emit("Apple 报错：" + _state_detail(item))
        if state == "COMPLETE":
            emit("Apple 已接收该构建并通过校验。")
            return {"upload_id": upload_id, "file_id": file_id, "state": state}
        if state == "FAILED":
            details = "；".join(_state_detail(item) for item in state_object.get("errors") or [])
            raise AscApiError("Apple 处理失败：" + (details or "未返回具体原因"))
    raise AscApiError("等待 Apple 处理超时（60 分钟），请稍后到 TestFlight 查看")


# ---------------------------------------------------------------- 证书助手
#
# 证书由 Apple 用 CSR 签发，本地负责生成密钥/CSR、合成 .p12、下载与解析描述文件；
# 申请证书、拉取描述文件走 App Store Connect API，权限不足时回退到开发者网站手动上传。

CERT_TYPE_CHOICES = [
    ("iOS Distribution", "IOS_DISTRIBUTION", "iOS 发布证书，HBuilderX 云打包签名用"),
    ("Apple Distribution", "DISTRIBUTION", "统一发布证书（含 iOS / macOS）"),
    ("iOS Development", "IOS_DEVELOPMENT", "开发调试证书"),
    ("Apple Push Services", "APPLE_PUSH_SERVICES", "推送证书（uni-push 用）"),
]

PROFILE_TYPE_CHOICES = [
    ("App Store", "IOS_APP_STORE"),
    ("Ad Hoc", "IOS_APP_ADHOC"),
    ("Development", "IOS_APP_DEVELOPMENT"),
]

PORTAL_CERT_URL = "https://developer.apple.com/account/resources/certificates/list"
PORTAL_PROFILE_URL = "https://developer.apple.com/account/resources/profiles/list"
WWDR_URLS = [
    "https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer",
    "https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer",
    "https://www.apple.com/certificateauthority/AppleWWDRCAG2.cer",
]


def cert_type_label(code: str) -> str:
    for label, value, _hint in CERT_TYPE_CHOICES:
        if value == (code or "").upper():
            return label
    return code or ""


def profile_type_label(code: str) -> str:
    for label, value in PROFILE_TYPE_CHOICES:
        if value == (code or "").upper():
            return label
    return {"IOS_APP_INHOUSE": "In-House"}.get((code or "").upper(), code or "")


def load_cert_index() -> list[dict]:
    try:
        if CERT_INDEX_PATH.exists():
            data = json.loads(CERT_INDEX_PATH.read_text("utf-8"))
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
    except Exception:
        pass
    return []


def save_cert_index(items: list[dict]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CERT_INDEX_PATH.write_text(json.dumps(items, ensure_ascii=False, indent=2), "utf-8")


def _cert_datetime(cert, attr: str):
    return getattr(cert, attr + "_utc", None) or getattr(cert, attr)


def fmt_when(value) -> str:
    try:
        return value.strftime("%Y-%m-%d")
    except Exception:
        return ""


def days_left(value) -> int:
    try:
        now = datetime.now(value.tzinfo) if value.tzinfo else datetime.now()
        return max(0, (value - now).days)
    except Exception:
        return 0


def load_certificate_file(path: str):
    raw = Path(path).read_bytes()
    try:
        return x509.load_der_x509_certificate(raw)
    except Exception:
        return x509.load_pem_x509_certificate(raw)


def _cert_name(name, oid) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return str(name.get_attributes_for_oid(oid)[0].value)
    except Exception:
        return ""


def describe_certificate(cert) -> dict:
    not_before = _cert_datetime(cert, "not_valid_before")
    not_after = _cert_datetime(cert, "not_valid_after")
    return {
        "cn": _cert_name(cert.subject, NameOID.COMMON_NAME),
        "org": _cert_name(cert.subject, NameOID.ORGANIZATION_NAME),
        "serial": format(cert.serial_number, "X"),
        "not_before": not_before,
        "not_after": not_after,
        "not_before_text": fmt_when(not_before),
        "not_after_text": fmt_when(not_after),
        "days_left": days_left(not_after),
        "issuer": _cert_name(cert.issuer, NameOID.COMMON_NAME),
    }


def filing_cert_info(cert) -> dict:
    """备案所需的证书公钥与指纹（iOS 的“签名MD5值”实际填 SHA-1）。"""
    public_key = cert.public_key()
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sha1 = cert.fingerprint(hashes.SHA1())
    md5 = cert.fingerprint(hashes.MD5())
    not_after = _cert_datetime(cert, "not_valid_after")
    if isinstance(public_key, rsa.RSAPublicKey):
        key_algorithm = f"RSA {public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_algorithm = f"EC {public_key.curve.name}"
    else:
        key_algorithm = type(public_key).__name__
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cn = _cert_name(cert.subject, NameOID.COMMON_NAME)
    return {
        "cn": cn,
        "serial": format(cert.serial_number, "X"),
        "not_after_text": fmt_when(not_after),
        "key_algorithm": key_algorithm,
        "pubkey_pem": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii").strip(),
        "pubkey_b64": base64.b64encode(spki).decode("ascii"),
        "pubkey_hex": spki.hex().upper(),
        "pubkey_hex_spaced": spki.hex(" ").upper(),
        "sha1": sha1.hex().upper(),
        "sha1_colon": ":".join(f"{byte:02X}" for byte in sha1),
        "md5": md5.hex().upper(),
    }


def _profile_payload(raw: bytes) -> dict:
    start = raw.find(b"<?xml")
    end = raw.rfind(b"</plist>")
    if start < 0 or end < 0:
        raise ValueError("不是有效的 .mobileprovision 文件")
    return plistlib.loads(raw[start:end + len(b"</plist>")])


def filing_info_from_certificate(cert, source: str = "", bundle_id: str = "") -> dict:
    return {
        "bundle_id": bundle_id,
        "cert": filing_cert_info(cert),
        "cert_count": 1,
        "source": source,
        "profile_name": "",
        "team": "",
    }


def filing_info_from_profile(raw: bytes, source: str = "") -> dict:
    payload = _profile_payload(raw)
    entitlements = payload.get("Entitlements") or {}
    app_id = str(entitlements.get("application-identifier") or "")
    bundle_id = app_id.split(".", 1)[1] if "." in app_id else ""
    certs = []
    for der in payload.get("DeveloperCertificates") or []:
        try:
            certs.append(filing_cert_info(x509.load_der_x509_certificate(der)))
        except Exception:
            continue
    if not certs:
        raise ValueError("描述文件里没有可读取的证书")
    preferred = certs[0]
    if len(certs) > 1:
        preferred = next((item for item in certs if "distribution" in item["cn"].lower()), certs[0])
    return {
        "bundle_id": bundle_id,
        "cert": preferred,
        "cert_count": len(certs),
        "source": source,
        "profile_name": str(payload.get("Name") or ""),
        "team": "、".join(payload.get("TeamIdentifier") or []),
    }


def filing_info_from_cert_file(path: str) -> dict:
    return filing_info_from_certificate(load_certificate_file(path), source=path)


def filing_info_from_p12(path: str, password: str) -> dict:
    _key, cert, _chain = pkcs12.load_key_and_certificates(
        Path(path).read_bytes(), password.encode("utf-8"),
    )
    if cert is None:
        raise ValueError("P12 中没有证书")
    return filing_info_from_certificate(cert, source=path)


def filing_info_from_ipa(path: str) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        bundle_id = ""
        for name in names:
            if name.startswith("Payload/") and name.count("/") == 2 and name.endswith(".app/Info.plist"):
                payload = plistlib.loads(archive.read(name))
                bundle_id = str(payload.get("CFBundleIdentifier") or "")
                break
        profile_name = ""
        for name in names:
            if (
                name.startswith("Payload/")
                and name.count("/") == 2
                and name.endswith(".app/embedded.mobileprovision")
            ):
                profile_name = name
                break
        if not profile_name:
            raise ValueError(
                "IPA 中没有 embedded.mobileprovision（App Store 下载的包会被剥离），\n"
                "请改用打包时使用的 .cer 或 .p12 文件。"
            )
        info = filing_info_from_profile(archive.read(profile_name), source=path)
    info["bundle_id"] = bundle_id or info["bundle_id"]
    return info


def generate_key_and_csr(cn: str, algorithm: str = "rsa") -> tuple[bytes, bytes]:
    if not cn.strip():
        raise ValueError("通用名称（CN）不能为空")
    if algorithm == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn.strip())]))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, csr.public_bytes(serialization.Encoding.PEM)


def build_p12(cer_path: str, key_path: str, out_path: str, password: str, chain_paths=()) -> dict:
    if not password:
        raise ValueError("p12 密码不能为空")
    cert = load_certificate_file(cer_path)
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("证书与私钥不匹配，请确认选择的是同一对密钥。")
    chain = []
    for item in chain_paths:
        if item and Path(item).is_file():
            chain.append(load_certificate_file(item))
    name = (describe_certificate(cert).get("cn") or "ipa").encode("utf-8")
    payload = pkcs12.serialize_key_and_certificates(
        name=name,
        key=key,
        cert=cert,
        cas=chain,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_bytes(payload)
    if hasattr(os, "chmod"):
        try:
            os.chmod(out_path, 0o600)
        except Exception:
            pass
    return {"size": len(payload), "chain": len(chain)}


def fetch_wwdr_chain(target_dir: Path) -> list[str]:
    target_dir.mkdir(parents=True, exist_ok=True)
    saved: list[str] = []
    for url in WWDR_URLS:
        name = url.rsplit("/", 1)[-1]
        path = target_dir / name
        if path.is_file() and path.stat().st_size > 0:
            saved.append(str(path))
            continue
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(request, timeout=20) as response:
                data = response.read()
            if data.startswith(b"-----BEGIN") or data[:1] == b"\x30":
                path.write_bytes(data)
                saved.append(str(path))
        except Exception:
            continue
    return saved


def parse_mobileprovision(path: str) -> dict:
    payload = _profile_payload(Path(path).read_bytes())
    entitlements = payload.get("Entitlements") or {}
    if payload.get("ProvisionsAllDevices"):
        profile_type = "In-House"
    elif payload.get("ProvisionedDevices"):
        profile_type = "Development" if entitlements.get("get-task-allow") else "Ad Hoc"
    else:
        profile_type = "App Store"
    expires = payload.get("ExpirationDate")
    serials = []
    if not CRYPTO_ERROR:
        for raw_cert in payload.get("DeveloperCertificates") or []:
            try:
                serials.append(format(x509.load_der_x509_certificate(raw_cert).serial_number, "X"))
            except Exception:
                continue
    return {
        "name": str(payload.get("Name") or ""),
        "uuid": str(payload.get("UUID") or ""),
        "type": profile_type,
        "app_id": str(entitlements.get("application-identifier") or ""),
        "team": "、".join(payload.get("TeamIdentifier") or []),
        "cert_serials": serials,
        "expires": expires,
        "expires_text": fmt_when(expires) if expires else "",
        "path": path,
    }


def token_from_config(cfg: dict) -> AscToken:
    return AscToken(
        key_path=str(cfg.get("api_key_path") or ""),
        key_id=str(cfg.get("api_key_id") or "").strip(),
        key_type=str(cfg.get("api_key_type") or "team"),
        issuer=str(cfg.get("api_issuer") or "").strip(),
    )


def _write_cert_content(content_b64: str, out_path: Path) -> Path:
    raw = base64.b64decode(content_b64)
    if raw.startswith(b"-----BEGIN"):
        try:
            x509.load_pem_x509_certificate(raw)
        except Exception as exc:
            raise AscApiError(f"Apple 返回的证书内容无法解析：{exc}") from None
    else:
        try:
            x509.load_der_x509_certificate(raw)
        except Exception as exc:
            raise AscApiError(f"Apple 返回的证书内容无法解析：{exc}") from None
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(raw)
    return out_path


def list_remote_certificates(token: AscToken) -> list[dict]:
    query = urllib.parse.urlencode(
        {
            "limit": "200",
            "fields[certificates]": "name,displayName,certificateType,expirationDate,serialNumber,certificateContent",
        }
    )
    payload = api_request("GET", f"/v1/certificates?{query}", token.value())
    items = []
    for item in payload.get("data") or []:
        attrs = item.get("attributes") or {}
        expires = None
        text = str(attrs.get("expirationDate") or "")
        if text:
            try:
                expires = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                expires = None
        items.append(
            {
                "id": str(item.get("id") or ""),
                "name": str(attrs.get("displayName") or attrs.get("name") or ""),
                "type": str(attrs.get("certificateType") or ""),
                "serial": str(attrs.get("serialNumber") or ""),
                "expires": expires,
                "expires_text": fmt_when(expires) if expires else "—",
                "days_left": days_left(expires) if expires else None,
                "content": str(attrs.get("certificateContent") or ""),
            }
        )
    items.sort(key=lambda entry: entry["expires"].timestamp() if entry["expires"] else 0, reverse=True)
    return items


def create_remote_certificate(token: AscToken, csr_pem: bytes, cert_type: str) -> dict:
    payload = {
        "data": {
            "type": "certificates",
            "attributes": {
                "certificateType": cert_type,
                "csrContent": csr_pem.decode("ascii").strip(),
            },
        }
    }
    data = api_request("POST", "/v1/certificates", token.value(), payload).get("data") or {}
    attrs = data.get("attributes") or {}
    return {
        "id": str(data.get("id") or ""),
        "content": str(attrs.get("certificateContent") or ""),
        "expires_text": str(attrs.get("expirationDate") or ""),
        "serial": str(attrs.get("serialNumber") or ""),
    }


def list_remote_profiles(token: AscToken) -> list[dict]:
    query = urllib.parse.urlencode(
        {
            "limit": "200",
            "fields[profiles]": "name,platform,profileType,profileState,uuid,expirationDate",
        }
    )
    payload = api_request("GET", f"/v1/profiles?{query}", token.value())
    items = []
    for item in payload.get("data") or []:
        attrs = item.get("attributes") or {}
        expires = None
        text = str(attrs.get("expirationDate") or "")
        if text:
            try:
                expires = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                expires = None
        items.append(
            {
                "id": str(item.get("id") or ""),
                "name": str(attrs.get("name") or ""),
                "type": str(attrs.get("profileType") or ""),
                "state": str(attrs.get("profileState") or ""),
                "uuid": str(attrs.get("uuid") or ""),
                "expires": expires,
                "expires_text": fmt_when(expires) if expires else "—",
                "days_left": days_left(expires) if expires else None,
            }
        )
    items.sort(key=lambda entry: entry["expires"].timestamp() if entry["expires"] else 0, reverse=True)
    return items


def download_remote_profile(token: AscToken, profile_id: str, out_dir: Path) -> dict:
    query = urllib.parse.urlencode(
        {"fields[profiles]": "name,profileType,profileState,uuid,expirationDate,profileContent"}
    )
    data = api_request("GET", f"/v1/profiles/{profile_id}?{query}", token.value()).get("data") or {}
    attrs = data.get("attributes") or {}
    content = str(attrs.get("profileContent") or "")
    if not content:
        raise AscApiError("Apple 未返回描述文件内容")
    safe_name = re.sub(r"[^\w.\-]+", "_", str(attrs.get("name") or profile_id))
    out_path = out_dir / f"{safe_name}.mobileprovision"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(base64.b64decode(content))
    info = parse_mobileprovision(str(out_path))
    info["id"] = profile_id
    info["state"] = str(attrs.get("profileState") or "")
    return info


def create_remote_profile(
    token: AscToken,
    name: str,
    profile_type: str,
    bundle_id: str,
    cert_ids,
    device_ids=(),
    out_dir: Path | None = None,
) -> dict:
    relationships = {
        "bundleId": {"data": {"type": "bundleIds", "id": bundle_id}},
        "certificates": {
            "data": [{"type": "certificates", "id": cert_id} for cert_id in cert_ids]
        },
    }
    if device_ids:
        relationships["devices"] = {
            "data": [{"type": "devices", "id": device_id} for device_id in device_ids]
        }
    payload = {
        "data": {
            "type": "profiles",
            "attributes": {"name": name, "profileType": profile_type},
            "relationships": relationships,
        }
    }
    data = api_request("POST", "/v1/profiles", token.value(), payload).get("data") or {}
    attrs = data.get("attributes") or {}
    content = str(attrs.get("profileContent") or "")
    if not content:
        raise AscApiError("描述文件已创建，但 Apple 未返回文件内容")
    safe_name = re.sub(r"[^\w.\-]+", "_", name)
    target_dir = Path(out_dir) if out_dir else PROFILE_DIR
    out_path = target_dir / f"{safe_name}.mobileprovision"
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(base64.b64decode(content))
    info = parse_mobileprovision(str(out_path))
    info["id"] = str(data.get("id") or "")
    info["state"] = str(attrs.get("profileState") or "")
    return info


def list_remote_bundle_ids(token: AscToken) -> list[dict]:
    query = urllib.parse.urlencode(
        {"limit": "200", "fields[bundleIds]": "identifier,name,platform", "sort": "identifier"}
    )
    payload = api_request("GET", f"/v1/bundleIds?{query}", token.value())
    return [
        {
            "id": str(item.get("id") or ""),
            "identifier": str((item.get("attributes") or {}).get("identifier") or ""),
            "name": str((item.get("attributes") or {}).get("name") or ""),
        }
        for item in payload.get("data") or []
    ]


def list_remote_devices(token: AscToken) -> list[dict]:
    query = urllib.parse.urlencode(
        {
            "limit": "200",
            "fields[devices]": "name,udid,platform,status",
            "filter[status]": "ENABLED",
        }
    )
    payload = api_request("GET", f"/v1/devices?{query}", token.value())
    return [
        {
            "id": str(item.get("id") or ""),
            "name": str((item.get("attributes") or {}).get("name") or ""),
            "udid": str((item.get("attributes") or {}).get("udid") or ""),
        }
        for item in payload.get("data") or []
    ]


# ---------------------------------------------------------------- 主窗口


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.history = load_history()
        self.events: queue.Queue = queue.Queue()
        self.uploading = False
        self.cancel_requested = False
        self.current_ipa = ""
        self.current_info: dict | None = None
        self.last_log_path: Path | None = None
        self.started_at = 0.0
        self.last_error_line = ""
        self.history_view: list[dict] = []

        self._setup_window()
        self._build_ui()
        self._load_settings_into_form()

        if CONFIG_PATH.exists():
            self.nb.select(self.tab_upload)
            self._status("请选择 IPA 文件后开始上传", "muted")
        else:
            self.nb.select(self.tab_settings)
            self._status("请选择 IPA 文件后开始上传", "muted")
            self._settings_status("首次使用：请先填写参数并保存", "muted")
        self._log_line("就绪。选择 IPA 文件后点击“开始上传”。")

        self.refresh_history()
        self._refresh_cert_archive()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)

    # ------------------------------------------------------------ 外观

    def _setup_window(self) -> None:
        self.scale = max(1.0, self.winfo_fpixels("1i") / 96.0)

        def px(value: float) -> int:
            return int(round(value * self.scale))

        self.px = px

        self.title(APP_TITLE)
        icon = app_icon_path()
        if icon:
            try:
                self.iconbitmap(icon)
            except Exception:
                pass
        width, height = px(1020), px(790)
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2 - px(20))
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(px(920), px(720))
        self.configure(bg="#eef1f5")

        families = set(tkfont.families(self))
        self.ui_family = "Microsoft YaHei UI" if "Microsoft YaHei UI" in families else "Microsoft YaHei"
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            try:
                tkfont.nametofont(name).configure(family=self.ui_family, size=10)
            except Exception:
                pass

        style = ttk.Style(self)
        for theme in ("vista", "winnative", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Treeview", rowheight=px(28))
        style.configure("Treeview.Heading", font=(self.ui_family, 9, "bold"))
        style.configure("TNotebook.Tab", padding=(px(20), px(8)))
        style.configure("TLabelframe.Label", font=(self.ui_family, 10, "bold"))
        style.configure("Hint.TLabel", foreground=COLOR_MUTED, font=(self.ui_family, 9))
        style.configure("Value.TLabel", font=(self.ui_family, 10, "bold"))

    def _build_ui(self) -> None:
        px = self.px
        header = tk.Frame(self, bg=COLOR_HEADER, height=px(68))
        header.pack(fill="x")
        header.pack_propagate(False)
        tk.Label(
            header, text=APP_TITLE, bg=COLOR_HEADER, fg="white",
            font=(self.ui_family, 16, "bold"),
        ).pack(side="left", padx=px(22))
        tk.Label(
            header, text="证书 · 备案 · 上架", bg=COLOR_HEADER, fg="#9fb6cf",
            font=(self.ui_family, 9),
        ).pack(side="right", padx=px(22))

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=px(14), pady=(px(12), px(14)))
        self.tab_upload = ttk.Frame(self.nb, padding=px(14))
        self.tab_cert = ttk.Frame(self.nb, padding=px(14))
        self.tab_filing = ttk.Frame(self.nb, padding=px(14))
        self.tab_settings = ttk.Frame(self.nb, padding=px(14))
        self.nb.add(self.tab_upload, text=" 上传 ")
        self.nb.add(self.tab_cert, text=" 证书 ")
        self.nb.add(self.tab_filing, text=" 备案 ")
        self.nb.add(self.tab_settings, text=" 设置 ")

        self._build_upload_tab()
        self._build_cert_tab()
        self._build_filing_tab()
        self._build_settings_tab()

    # ------------------------------------------------------------ 上传页

    def _build_upload_tab(self) -> None:
        px = self.px
        tab = self.tab_upload
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        pkg = ttk.LabelFrame(tab, text=" 应用包 ", padding=(px(14), px(12)))
        pkg.grid(row=0, column=0, sticky="ew")
        pkg.columnconfigure(1, weight=1)

        self.btn_pick = ttk.Button(pkg, text="选择 IPA 文件…", command=self.pick_ipa)
        self.btn_pick.grid(row=0, column=0, sticky="w")
        self.lbl_ipa = ttk.Label(pkg, text="尚未选择文件", foreground=COLOR_MUTED)
        self.lbl_ipa.grid(row=0, column=1, sticky="w", padx=(px(12), 0))

        info = ttk.Frame(pkg)
        info.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(px(12), 0))
        self.info_vars: dict[str, tk.StringVar] = {}
        captions = [("bundle", "Bundle ID"), ("version", "版本号"), ("build", "构建号"), ("size", "文件大小")]
        for index, (key, caption) in enumerate(captions):
            info.columnconfigure(index, weight=1)
            cell = ttk.Frame(info)
            cell.grid(row=0, column=index, sticky="w", padx=(0, px(18)))
            ttk.Label(cell, text=caption, style="Hint.TLabel").pack(anchor="w")
            var = tk.StringVar(value="—")
            self.info_vars[key] = var
            ttk.Label(cell, textvariable=var, style="Value.TLabel").pack(anchor="w")

        up = ttk.LabelFrame(tab, text=" 上传 ", padding=(px(14), px(12)))
        up.grid(row=1, column=0, sticky="ew", pady=(px(12), 0))
        up.columnconfigure(2, weight=1)

        self.btn_upload = ttk.Button(up, text="开始上传", command=self.start_upload)
        self.btn_upload.grid(row=0, column=0, sticky="w")
        self.btn_cancel = ttk.Button(up, text="取消", command=self.cancel_upload, state="disabled")
        self.btn_cancel.grid(row=0, column=1, sticky="w", padx=(px(8), 0))
        self.lbl_status = ttk.Label(up, text="", foreground=COLOR_MUTED)
        self.lbl_status.grid(row=0, column=2, sticky="w", padx=(px(14), 0))

        self.progress = ttk.Progressbar(up, mode="determinate", maximum=100)
        self.progress.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(px(10), px(8)))

        self.log_text = ScrolledText(
            up, height=6, wrap="word", font=("Consolas", 9),
            bg="#111820", fg="#dbe6f2", insertbackground="#dbe6f2",
            relief="flat", borderwidth=0, state="disabled",
        )
        self.log_text.grid(row=2, column=0, columnspan=3, sticky="ew")

        hist = ttk.LabelFrame(tab, text=" 上传历史 ", padding=(px(14), px(12)))
        hist.grid(row=2, column=0, sticky="nsew", pady=(px(12), 0))
        hist.columnconfigure(0, weight=1)
        hist.rowconfigure(0, weight=1)

        columns = ("time", "name", "version", "size", "status", "duration")
        headings = {
            "time": "上传时间", "name": "文件", "version": "版本(构建)",
            "size": "大小", "status": "结果", "duration": "耗时",
        }
        widths = {"time": 160, "name": 300, "version": 120, "size": 100, "status": 80, "duration": 90}
        self.tree = ttk.Treeview(hist, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=px(widths[col]), anchor="w", stretch=(col == "name"))
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.tag_configure("ok", foreground=COLOR_OK)
        self.tree.tag_configure("fail", foreground=COLOR_ERR)
        self.tree.tag_configure("cancel", foreground=COLOR_MUTED)

        scroll = ttk.Scrollbar(hist, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<Double-1>", lambda _event: self.open_selected_log())
        self.tree.bind("<Button-3>", self._show_history_menu)

        buttons = ttk.Frame(hist)
        buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(px(10), 0))
        ttk.Button(buttons, text="打开日志", command=self.open_selected_log).pack(side="left")
        ttk.Button(buttons, text="打开所在目录", command=self.reveal_selected_log).pack(side="left", padx=px(8))
        ttk.Button(buttons, text="复制命令", command=self.copy_selected_command).pack(side="left")
        ttk.Button(buttons, text="清空历史", command=self.clear_history).pack(side="right")
        ttk.Button(buttons, text="日志目录", command=self.open_log_dir).pack(side="right", padx=px(8))
        ttk.Label(buttons, text="双击记录可查看日志", style="Hint.TLabel").pack(side="left", padx=(px(16), 0))

        self.history_menu = tk.Menu(self, tearoff=False)
        self.history_menu.add_command(label="查看日志", command=self.open_selected_log)
        self.history_menu.add_command(label="打开所在目录", command=self.reveal_selected_log)
        self.history_menu.add_command(label="复制上传命令", command=self.copy_selected_command)
        self.history_menu.add_separator()
        self.history_menu.add_command(label="删除这条记录", command=self.delete_selected_record)

    # ------------------------------------------------------------ 设置页

    def _build_settings_tab(self) -> None:
        px = self.px
        tab = self.tab_settings
        tab.columnconfigure(0, weight=1)

        acct = ttk.LabelFrame(tab, text=" App Store Connect API Key ", padding=(px(14), px(12)))
        acct.grid(row=0, column=0, sticky="ew")
        acct.columnconfigure(1, weight=1)

        ttk.Label(
            acct,
            text="使用 App Store Connect API Key（.p8）直传，不需要安装 Transporter。",
            style="Hint.TLabel",
        ).grid(row=0, column=0, columnspan=4, sticky="w")

        ttk.Label(acct, text="Key ID").grid(row=1, column=0, sticky="w", pady=(px(10), 0))
        self.var_key_id = tk.StringVar()
        ttk.Entry(acct, textvariable=self.var_key_id).grid(
            row=1, column=1, sticky="ew", padx=px(8), pady=(px(10), 0),
        )

        ttk.Label(acct, text="Issuer ID").grid(row=2, column=0, sticky="w", pady=(px(8), 0))
        self.var_issuer = tk.StringVar()
        ttk.Entry(acct, textvariable=self.var_issuer).grid(
            row=2, column=1, sticky="ew", padx=px(8), pady=(px(8), 0),
        )

        ttk.Label(acct, text="Key 类型").grid(row=3, column=0, sticky="w", pady=(px(8), 0))
        self.var_key_type = tk.StringVar(value="team")
        types = ttk.Frame(acct)
        types.grid(row=3, column=1, sticky="w", padx=px(8), pady=(px(8), 0))
        ttk.Radiobutton(types, text="Team", variable=self.var_key_type, value="team").pack(side="left")
        ttk.Radiobutton(types, text="Individual", variable=self.var_key_type, value="individual").pack(
            side="left", padx=(px(12), 0),
        )

        ttk.Label(acct, text=".p8 文件").grid(row=4, column=0, sticky="w", pady=(px(8), 0))
        self.var_key_path = tk.StringVar()
        ttk.Entry(acct, textvariable=self.var_key_path).grid(
            row=4, column=1, sticky="ew", padx=px(8), pady=(px(8), 0),
        )
        ttk.Button(acct, text="浏览…", command=self._browse_key_file).grid(row=4, column=2, pady=(px(8), 0))
        ttk.Label(
            acct,
            text="在 App Store Connect → 用户和访问 → 集成 中创建密钥并下载 .p8。",
            style="Hint.TLabel",
        ).grid(row=5, column=0, columnspan=3, sticky="w", pady=(px(6), 0))

        ttk.Label(acct, text="App 数字 ID（可留空）").grid(row=6, column=0, sticky="w", pady=(px(12), 0))
        self.var_app_id = tk.StringVar()
        ttk.Entry(acct, textvariable=self.var_app_id).grid(
            row=6, column=1, sticky="ew", padx=px(8), pady=(px(12), 0),
        )
        ttk.Label(
            acct,
            text="留空时按 IPA 的 Bundle ID 自动识别应用。",
            style="Hint.TLabel",
        ).grid(row=7, column=0, columnspan=4, sticky="w", pady=(px(6), 0))

        other = ttk.LabelFrame(tab, text=" 其他 ", padding=(px(14), px(12)))
        other.grid(row=1, column=0, sticky="ew", pady=(px(12), 0))
        other.columnconfigure(1, weight=1)

        ttk.Label(other, text="默认 IPA 目录").grid(row=0, column=0, sticky="w")
        self.var_ipa_dir = tk.StringVar()
        ttk.Entry(other, textvariable=self.var_ipa_dir).grid(row=0, column=1, sticky="ew", padx=px(8))
        ttk.Button(other, text="浏览…", command=lambda: self._browse_dir(self.var_ipa_dir)).grid(row=0, column=2)

        actions = ttk.Frame(tab)
        actions.grid(row=2, column=0, sticky="w", pady=(px(16), 0))
        ttk.Button(actions, text="保存设置", command=self.save_settings).pack(side="left")
        self.lbl_settings_status = ttk.Label(actions, text="", foreground=COLOR_MUTED)
        self.lbl_settings_status.pack(side="left", padx=(px(14), 0))

    # ------------------------------------------------------------ 设置逻辑

    def _load_settings_into_form(self) -> None:
        cfg = self.cfg
        self.var_app_id.set(cfg.get("app_apple_id", ""))
        self.var_key_id.set(cfg.get("api_key_id", ""))
        self.var_issuer.set(cfg.get("api_issuer", ""))
        self.var_key_type.set(cfg.get("api_key_type", "team"))
        self.var_key_path.set(cfg.get("api_key_path", ""))
        self.var_ipa_dir.set(cfg.get("default_ipa_dir", ""))

    def _browse_dir(self, var: tk.StringVar) -> None:
        current = var.get() if var.get() and Path(var.get()).exists() else str(Path.home())
        chosen = filedialog.askdirectory(initialdir=current)
        if chosen:
            var.set(chosen)

    def _browse_key_file(self) -> None:
        chosen = filedialog.askopenfilename(
            title="选择 API 私钥",
            filetypes=[("API 私钥", "*.p8"), ("所有文件", "*.*")],
        )
        if chosen:
            self.var_key_path.set(chosen)

    def save_settings(self) -> None:
        cfg = dict(self.cfg)
        app_apple_id = self.var_app_id.get().strip()
        if app_apple_id and not app_apple_id.isdigit():
            messagebox.showerror(
                "参数无效",
                "App 数字 ID 只能填纯数字，留空则按 IPA 的 Bundle ID 自动识别。",
            )
            return
        key_id = self.var_key_id.get().strip()
        issuer = self.var_issuer.get().strip()
        key_path = self.var_key_path.get().strip()
        if not key_id or not issuer:
            messagebox.showerror("缺少参数", "请填写 API Key 的 Key ID 和 Issuer ID。")
            return
        if not Path(key_path).is_file():
            messagebox.showerror("缺少参数", "请选择有效的 .p8 私钥文件。")
            return

        cfg["app_apple_id"] = app_apple_id
        cfg["api_key_id"] = key_id
        cfg["api_issuer"] = issuer
        cfg["api_key_type"] = self.var_key_type.get() or "team"
        cfg["api_key_path"] = key_path
        cfg["default_ipa_dir"] = self.var_ipa_dir.get().strip()
        try:
            self._store_api_key(cfg)
        except Exception as exc:
            messagebox.showerror("私钥复制失败", str(exc))
            return

        save_config(cfg)
        self.cfg = cfg
        self._settings_status("设置已保存", "ok")
        self.nb.select(self.tab_upload)
        if self.current_ipa:
            self._status("设置已保存，可以开始上传", "muted")
        else:
            self._status("请选择 IPA 文件后开始上传", "muted")

    def _store_api_key(self, cfg: dict) -> Path:
        source = Path(cfg["api_key_path"])
        prefix = "ApiKey" if cfg.get("api_key_type") == "individual" else "AuthKey"
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        target = KEYS_DIR / f"{prefix}_{cfg['api_key_id']}.p8"
        if not target.exists() or target.read_bytes() != source.read_bytes():
            shutil.copy2(source, target)
        return target

    # ------------------------------------------------------------ 证书页

    def _build_cert_tab(self) -> None:
        px = self.px
        tab = self.tab_cert
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        archive = ttk.LabelFrame(tab, text=" 证书档案 ", padding=(px(14), px(12)))
        archive.grid(row=0, column=0, sticky="ew")
        archive.columnconfigure(0, weight=1)

        bar = ttk.Frame(archive)
        bar.grid(row=0, column=0, sticky="ew")
        ttk.Button(bar, text="新建证书申请…", command=self._open_cert_wizard).pack(side="left")
        ttk.Button(bar, text="从 Apple 同步证书", command=self._cert_sync_certificates).pack(
            side="left", padx=px(8),
        )
        ttk.Button(bar, text="导入 .cer…", command=self._cert_import_cer).pack(side="left")
        ttk.Button(bar, text="合成 P12…", command=self._cert_export_p12).pack(side="left", padx=px(8))
        ttk.Button(bar, text="移除档案", command=self._cert_delete_entry).pack(side="left")
        ttk.Button(bar, text="打开证书目录", command=self._cert_open_dir).pack(side="right")
        ttk.Button(bar, text="刷新", command=self._refresh_cert_archive).pack(side="right", padx=px(8))

        columns = ("name", "type", "expires", "left", "key", "p12")
        headings = {
            "name": "名称", "type": "类型", "expires": "有效期至",
            "left": "剩余", "key": "私钥", "p12": "P12",
        }
        widths = {"name": 240, "type": 200, "expires": 110, "left": 90, "key": 70, "p12": 80}
        self.cert_tree = ttk.Treeview(archive, columns=columns, show="headings", selectmode="browse", height=7)
        for col in columns:
            self.cert_tree.heading(col, text=headings[col])
            self.cert_tree.column(col, width=px(widths[col]), anchor="w", stretch=(col == "name"))
        self.cert_tree.grid(row=1, column=0, sticky="ew", pady=(px(10), 0))
        self.cert_tree.tag_configure("ok", foreground=COLOR_OK)
        self.cert_tree.tag_configure("warn", foreground="#b26a00")
        self.cert_tree.tag_configure("expired", foreground=COLOR_ERR)
        self.cert_tree.tag_configure("pending", foreground=COLOR_MUTED)
        self.cert_tree.bind("<<TreeviewSelect>>", lambda _event: self._show_cert_detail())
        self.cert_tree.bind("<Double-1>", self._on_cert_double_click)
        ttk.Label(
            archive, text="提示：双击“私钥”或“P12”列，可直接选择本地文件补充。",
            style="Hint.TLabel",
        ).grid(row=2, column=0, sticky="w", pady=(px(6), 0))

        bottom = ttk.Frame(tab)
        bottom.grid(row=1, column=0, sticky="nsew", pady=(px(12), 0))
        bottom.columnconfigure(0, weight=3)
        bottom.columnconfigure(1, weight=2)
        bottom.rowconfigure(0, weight=1)

        prof = ttk.LabelFrame(bottom, text=" 描述文件（Provisioning Profile） ", padding=(px(12), px(10)))
        prof.grid(row=0, column=0, sticky="nsew", padx=(0, px(12)))
        prof.columnconfigure(0, weight=1)
        prof.rowconfigure(1, weight=1)

        pbar = ttk.Frame(prof)
        pbar.grid(row=0, column=0, sticky="ew")
        ttk.Button(pbar, text="拉取列表", command=self._cert_refresh_profiles).pack(side="left")
        ttk.Button(pbar, text="下载选中", command=self._cert_download_profiles).pack(side="left", padx=px(8))
        ttk.Button(pbar, text="导入文件…", command=self._cert_import_profile).pack(side="left")
        ttk.Button(pbar, text="新建…", command=self._cert_create_profile_dialog).pack(side="right")
        ttk.Button(
            pbar, text="网站", command=lambda: webbrowser.open(PORTAL_PROFILE_URL),
        ).pack(side="right", padx=px(8))

        pcolumns = ("name", "source", "type", "state", "expires", "uuid")
        pheadings = {
            "name": "名称", "source": "来源", "type": "类型",
            "state": "状态", "expires": "到期", "uuid": "UUID",
        }
        pwidths = {"name": 170, "source": 50, "type": 100, "state": 70, "expires": 90, "uuid": 150}
        self.prof_tree = ttk.Treeview(prof, columns=pcolumns, show="headings", selectmode="extended", height=8)
        for col in pcolumns:
            self.prof_tree.heading(col, text=pheadings[col])
            self.prof_tree.column(col, width=px(pwidths[col]), anchor="w", stretch=(col == "name"))
        self.prof_tree.grid(row=1, column=0, sticky="nsew", pady=(px(8), 0))
        pscroll = ttk.Scrollbar(prof, orient="vertical", command=self.prof_tree.yview)
        pscroll.grid(row=1, column=1, sticky="ns", pady=(px(8), 0))
        pxscroll = ttk.Scrollbar(prof, orient="horizontal", command=self.prof_tree.xview)
        pxscroll.grid(row=2, column=0, sticky="ew")
        self.prof_tree.configure(yscrollcommand=pscroll.set, xscrollcommand=pxscroll.set)
        self.prof_tree.tag_configure("ok", foreground=COLOR_OK)
        self.prof_tree.tag_configure("warn", foreground="#b26a00")
        self.prof_tree.tag_configure("local", foreground=COLOR_INFO)

        detail = ttk.LabelFrame(bottom, text=" 详情 ", padding=(px(12), px(10)))
        detail.grid(row=0, column=1, sticky="nsew")
        detail.columnconfigure(0, weight=1)
        detail.rowconfigure(0, weight=1)
        self.cert_detail = ScrolledText(
            detail, height=10, wrap="word", font=("Consolas", 9),
            bg="#f7f9fb", fg="#1f2933", relief="flat", state="disabled",
        )
        self.cert_detail.grid(row=0, column=0, sticky="nsew")
        dbar = ttk.Frame(detail)
        dbar.grid(row=1, column=0, sticky="ew", pady=(px(8), 0))
        ttk.Button(dbar, text="打开所在目录", command=self._cert_reveal_selected).pack(side="left")
        ttk.Button(dbar, text="复制详情", command=self._cert_copy_detail).pack(side="left", padx=px(8))
        ttk.Button(dbar, text="备案信息", command=self._filing_from_selected_cert).pack(side="left")

        self.cert_status = ttk.Label(tab, text="", foreground=COLOR_MUTED)
        self.cert_status.grid(row=2, column=0, sticky="w", pady=(px(8), 0))

        self.cert_busy = False
        self.cert_index: list[dict] = []
        self.cert_view: list[dict] = []
        self.profile_view: list[dict] = []
        self.cert_detail_text = ""
        if CRYPTO_ERROR:
            self._cert_status(f"缺少 cryptography 依赖：{CRYPTO_ERROR}", "err")

    # ------------------------------------------------------------ 备案页

    def _build_filing_tab(self) -> None:
        px = self.px
        tab = self.tab_filing
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        src = ttk.LabelFrame(tab, text=" 选择文件 ", padding=(px(14), px(12)))
        src.grid(row=0, column=0, sticky="ew")
        src.columnconfigure(3, weight=1)
        ttk.Button(src, text="选择 IPA…", command=self._filing_pick_ipa).grid(row=0, column=0, sticky="w")
        ttk.Button(
            src, text="选择证书 / 描述文件…", command=self._filing_pick_cert,
        ).grid(row=0, column=1, sticky="w", padx=px(8))
        ttk.Button(
            src, text="从证书档案带入", command=self._filing_from_selected_cert,
        ).grid(row=0, column=2, sticky="w")
        self.filing_path = tk.StringVar(value="尚未选择文件")
        ttk.Label(
            src, textvariable=self.filing_path, style="Hint.TLabel",
        ).grid(row=0, column=3, sticky="w", padx=(px(12), 0))
        ttk.Label(
            src,
            text="iOS 备案口径：Bundle ID + 证书公钥 + 证书 SHA-1（表单里叫“签名MD5值”）。",
            style="Hint.TLabel",
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(px(8), 0))

        base = ttk.LabelFrame(tab, text=" 基础信息 ", padding=(px(14), px(10)))
        base.grid(row=1, column=0, sticky="ew", pady=(px(12), 0))
        base.columnconfigure(1, weight=1)
        self.filing_vars: dict[str, tk.StringVar] = {}
        rows = [
            ("bundle_id", "Bundle ID"),
            ("cn", "证书名称"),
            ("key_algorithm", "公钥算法"),
            ("serial", "序列号"),
            ("not_after", "证书有效期"),
            ("profile", "描述文件"),
        ]
        for index, (key, caption) in enumerate(rows):
            ttk.Label(base, text=caption, width=10).grid(row=index, column=0, sticky="w", pady=px(2))
            var = tk.StringVar(value="—")
            self.filing_vars[key] = var
            ttk.Entry(base, textvariable=var, state="readonly").grid(
                row=index, column=1, sticky="ew", padx=(px(8), px(8)), pady=px(2),
            )
            ttk.Button(
                base, text="复制", width=6, command=lambda k=key: self._filing_copy_var(k),
            ).grid(row=index, column=2, sticky="e", pady=px(2))

        pk = ttk.LabelFrame(tab, text=" 公钥 ", padding=(px(14), px(10)))
        pk.grid(row=2, column=0, sticky="nsew", pady=(px(12), 0))
        pk.columnconfigure(0, weight=1)
        pk.rowconfigure(0, weight=1)
        self.filing_pub_text = ScrolledText(
            pk, height=6, wrap="char", font=("Consolas", 9),
            bg="#f7f9fb", fg="#1f2933", relief="flat", state="disabled",
        )
        self.filing_pub_text.grid(row=0, column=0, sticky="nsew")
        pbar = ttk.Frame(pk)
        pbar.grid(row=1, column=0, sticky="w", pady=(px(8), 0))
        ttk.Button(
            pbar, text="复制 PEM", command=lambda: self._filing_copy("pubkey_pem", "公钥 PEM"),
        ).pack(side="left")
        ttk.Button(
            pbar, text="复制 Base64 单行",
            command=lambda: self._filing_copy("pubkey_b64", "公钥 Base64"),
        ).pack(side="left", padx=px(8))
        ttk.Button(
            pbar, text="复制十六进制",
            command=lambda: self._filing_copy("pubkey_hex", "公钥十六进制"),
        ).pack(side="left")
        ttk.Button(
            pbar, text="复制空格分隔",
            command=lambda: self._filing_copy("pubkey_hex_spaced", "公钥十六进制（空格）"),
        ).pack(side="left", padx=px(8))
        ttk.Label(
            pbar, text="十六进制即 Windows 证书“详细信息→公钥”的格式", style="Hint.TLabel",
        ).pack(side="left", padx=(px(8), 0))

        sig = ttk.LabelFrame(tab, text=" 签名指纹 ", padding=(px(14), px(10)))
        sig.grid(row=3, column=0, sticky="ew", pady=(px(12), 0))
        sig.columnconfigure(1, weight=1)
        self.filing_vars["sha1"] = tk.StringVar(value="—")
        self.filing_vars["sha1_colon"] = tk.StringVar(value="—")
        self.filing_vars["md5"] = tk.StringVar(value="—")
        sig_rows = [
            ("sha1", "SHA-1（备案填这个）", "SHA-1"),
            ("sha1_colon", "SHA-1（冒号分隔）", "SHA-1（冒号）"),
            ("md5", "证书 MD5（参考）", "证书 MD5"),
        ]
        for index, (key, caption, label) in enumerate(sig_rows):
            ttk.Label(sig, text=caption, width=18).grid(row=index, column=0, sticky="w", pady=px(2))
            ttk.Entry(
                sig, textvariable=self.filing_vars[key], state="readonly", font=("Consolas", 9),
            ).grid(row=index, column=1, sticky="ew", padx=(px(8), px(8)), pady=px(2))
            ttk.Button(
                sig, text="复制", width=6,
                command=lambda k=key, l=label: self._filing_copy(k, l),
            ).grid(row=index, column=2, sticky="e", pady=px(2))

        foot = ttk.Frame(tab)
        foot.grid(row=4, column=0, sticky="ew", pady=(px(12), 0))
        ttk.Button(foot, text="一键复制备案三项", command=self._filing_copy_all).pack(side="left")
        ttk.Label(
            foot, text="Bundle ID、公钥、签名 SHA-1 带标签一次复制", style="Hint.TLabel",
        ).pack(side="left", padx=(px(12), 0))
        self.filing_status = ttk.Label(foot, text="", foreground=COLOR_MUTED)
        self.filing_status.pack(side="right")

        self.filing_info: dict | None = None
        if CRYPTO_ERROR:
            self._filing_set_status(f"缺少 cryptography 依赖：{CRYPTO_ERROR}", "err")

    def _filing_set_status(self, text: str, color: str = "muted") -> None:
        palette = {"ok": COLOR_OK, "err": COLOR_ERR, "muted": COLOR_MUTED, "info": COLOR_INFO}
        self.filing_status.configure(text=text, foreground=palette.get(color, COLOR_MUTED))

    def _filing_ready(self) -> bool:
        if CRYPTO_ERROR:
            messagebox.showerror(
                "缺少依赖",
                "备案信息解析需要 cryptography 库：\n\npip install cryptography\n\n" + CRYPTO_ERROR,
            )
            return False
        return True

    def _filing_pick_ipa(self) -> None:
        if not self._filing_ready():
            return
        chosen = filedialog.askopenfilename(
            title="选择 IPA 文件",
            filetypes=[("iOS 应用包", "*.ipa"), ("所有文件", "*.*")],
        )
        if chosen:
            self._filing_load_ipa(chosen)

    def _filing_pick_cert(self) -> None:
        if not self._filing_ready():
            return
        chosen = filedialog.askopenfilename(
            title="选择证书或描述文件",
            filetypes=[
                ("证书 / 描述文件", "*.cer *.crt *.pem *.mobileprovision *.p12 *.pfx"),
                ("所有文件", "*.*"),
            ],
        )
        if chosen:
            self._filing_load_file(chosen)

    def _filing_load_file(self, path: str) -> None:
        if not self._filing_ready():
            return
        suffix = Path(path).suffix.lower()
        try:
            if suffix == ".ipa":
                self._filing_load_ipa(path)
                return
            if suffix == ".mobileprovision":
                info = filing_info_from_profile(Path(path).read_bytes(), path)
            elif suffix in (".p12", ".pfx"):
                password = self._ask_simple_password("读取 P12", "请输入该 P12 的导出密码：")
                if password is None:
                    return
                info = filing_info_from_p12(path, password)
            else:
                info = filing_info_from_cert_file(path)
        except Exception as exc:
            self._filing_set_status(f"读取失败：{exc}", "err")
            messagebox.showerror("无法解析", str(exc))
            return
        self._filing_apply(info, path)

    def _filing_load_ipa(self, path: str) -> None:
        if not self._filing_ready():
            return
        try:
            info = filing_info_from_ipa(path)
        except Exception as exc:
            self._filing_set_status(f"读取失败：{exc}", "err")
            messagebox.showerror("无法解析 IPA", str(exc))
            return
        self._filing_apply(info, path)

    def _filing_apply(self, info: dict, path: str = "") -> None:
        cert = info.get("cert") or {}
        self.filing_info = info
        self.filing_path.set(path or info.get("source") or "—")
        profile_text = " · ".join(
            part for part in (info.get("profile_name"), info.get("team")) if part
        ) or "—"
        if info.get("cert_count", 1) > 1:
            profile_text += f"（含 {info['cert_count']} 张证书，已优先取 Distribution）"
        values = {
            "bundle_id": info.get("bundle_id") or "",
            "cn": cert.get("cn") or "—",
            "key_algorithm": cert.get("key_algorithm") or "—",
            "serial": cert.get("serial") or "—",
            "not_after": cert.get("not_after_text") or "—",
            "profile": profile_text,
            "sha1": cert.get("sha1") or "—",
            "sha1_colon": cert.get("sha1_colon") or "—",
            "md5": cert.get("md5") or "—",
        }
        for key, value in values.items():
            self.filing_vars[key].set(value)
        self.filing_pub_text.configure(state="normal")
        self.filing_pub_text.delete("1.0", "end")
        self.filing_pub_text.insert("1.0", cert.get("pubkey_pem") or "")
        self.filing_pub_text.configure(state="disabled")
        if info.get("bundle_id"):
            self._filing_set_status("解析完成，可点右侧按钮复制", "ok")
        else:
            self._filing_set_status("解析完成；文件不含 Bundle ID，请手动填写", "info")
        self.nb.select(self.tab_filing)

    def _filing_copy_text(self, text: str, label: str) -> None:
        if not text:
            self._filing_set_status(f"暂无{label}可复制", "err")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        self._filing_set_status(f"已复制{label}", "ok")

    def _filing_copy(self, key: str, label: str) -> None:
        cert = (self.filing_info or {}).get("cert") or {}
        self._filing_copy_text(cert.get(key) or "", label)

    def _filing_copy_var(self, key: str) -> None:
        text = self.filing_vars[key].get()
        if not text or text == "—":
            self._filing_set_status("该项为空，无法复制", "err")
            return
        self._filing_copy_text(text, "到剪贴板")

    def _filing_copy_all(self) -> None:
        info = self.filing_info
        if not info:
            self._filing_set_status("请先选择文件完成解析", "err")
            return
        cert = info.get("cert") or {}
        text = (
            f"Bundle ID：{info.get('bundle_id') or ''}\n"
            f"公钥：{cert.get('pubkey_pem') or ''}\n"
            f"签名SHA-1：{cert.get('sha1') or ''}\n"
        )
        self._filing_copy_text(text, " Bundle ID、公钥、SHA-1")

    def _filing_from_selected_cert(self) -> None:
        entry = self._selected_cert_entry()
        if not entry:
            messagebox.showinfo("请选择证书", "请先在“证书”页选择一条证书档案，再查看备案信息。")
            return
        cer_path = entry.get("cer_path") or ""
        p12_path = entry.get("p12_path") or ""
        if cer_path and Path(cer_path).is_file():
            self._filing_load_file(cer_path)
        elif p12_path and Path(p12_path).is_file():
            self._filing_load_file(p12_path)
        else:
            messagebox.showinfo("没有证书文件", "该档案没有可读取的 .cer 或 .p12 文件。")

    def _cert_status(self, text: str, color: str = "muted") -> None:
        palette = {"ok": COLOR_OK, "err": COLOR_ERR, "muted": COLOR_MUTED, "info": COLOR_INFO}
        self.cert_status.configure(text=text, foreground=palette.get(color, COLOR_MUTED))

    def _cert_ready(self) -> bool:
        if CRYPTO_ERROR:
            messagebox.showerror(
                "缺少依赖",
                "证书功能需要 cryptography 库：\n\npip install cryptography\n\n" + CRYPTO_ERROR,
            )
            return False
        return True

    def _cert_api_token(self) -> AscToken | None:
        problem = self._runtime_problem()
        if problem:
            messagebox.showwarning(
                "无法连接 Apple",
                problem + "\n\n请到“设置”页补全 API Key。\n"
                "也可以走手动流程：在开发者网站申请证书后，用“导入 .cer…”添加档案。",
            )
            return None
        return token_from_config(self.cfg)

    def _run_cert_task(self, message: str, func, on_ok) -> None:
        if getattr(self, "cert_busy", False):
            messagebox.showinfo("请稍候", "上一个证书操作还在进行中。")
            return
        self.cert_busy = True
        self._cert_status(message, "muted")

        def worker() -> None:
            try:
                result = func()
            except Exception as exc:
                self.events.put(("cert_task", on_ok, None, str(exc)))
                return
            self.events.put(("cert_task", on_ok, result, ""))

        threading.Thread(target=worker, daemon=True).start()

    def _refresh_cert_archive(self) -> None:
        self.cert_index = load_cert_index()
        for item in self.cert_tree.get_children():
            self.cert_tree.delete(item)
        self.cert_view = list(reversed(self.cert_index))
        for entry in self.cert_view:
            not_after = entry.get("not_after") or ""
            left = None
            if not_after:
                try:
                    left = days_left(datetime.fromisoformat(not_after))
                except ValueError:
                    left = None
            if left is None:
                tag = "pending"
                left_text = "—"
            elif left <= 0:
                tag = "expired"
                left_text = "已过期"
            elif left < 30:
                tag = "warn"
                left_text = f"{left} 天"
            else:
                tag = "ok"
                left_text = f"{left} 天"
            has_key_file = bool(entry.get("key_path")) and Path(entry["key_path"]).is_file()
            has_p12 = bool(entry.get("p12_path")) and Path(entry["p12_path"]).is_file()
            has_key = has_key_file or has_p12
            if has_p12:
                p12_text = "已生成" if has_key_file else "已导入"
            elif has_key and entry.get("cer_path") and Path(entry["cer_path"]).is_file():
                p12_text = "未生成"
            elif has_key:
                p12_text = "待证书"
            else:
                p12_text = "缺私钥"
            self.cert_tree.insert(
                "", "end",
                values=(
                    entry.get("name", ""),
                    entry.get("type", ""),
                    entry.get("not_after_text") or not_after,
                    left_text,
                    ("有" if has_key_file else "P12 内") if has_key else "缺失",
                    p12_text,
                ),
                tags=(tag,),
            )
        if self.profile_view:
            self._fill_profile_tree(self.profile_view)
        if not self.cert_index and not self.cert_status.cget("text"):
            self._cert_status(
                "还没有证书档案：点“新建证书申请…”开始，或“从 Apple 同步证书”查看已有证书。", "muted",
            )

    def _on_cert_double_click(self, event) -> None:
        row = self.cert_tree.identify_row(event.y)
        if not row:
            return
        self.cert_tree.selection_set(row)
        index = self.cert_tree.index(row)
        if not (0 <= index < len(self.cert_view)):
            return
        entry = self.cert_view[index]
        column = self.cert_tree.identify_column(event.x)
        if column == "#5":
            self._cert_attach_key(entry)
        elif column == "#6":
            self._cert_attach_p12(entry)
        else:
            self._show_cert_detail()

    def _cert_attach_key(self, entry: dict) -> None:
        if not self._cert_ready():
            return
        chosen = filedialog.askopenfilename(
            title="选择与该证书配对的私钥",
            filetypes=[("私钥", "*.key *.pem"), ("所有文件", "*.*")],
        )
        if not chosen:
            return
        raw = Path(chosen).read_bytes()
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except TypeError:
            password = self._ask_simple_password("私钥已加密", "请输入该私钥的密码：")
            if password is None:
                return
            try:
                key = serialization.load_pem_private_key(raw, password=password.encode("utf-8"))
            except Exception:
                messagebox.showerror("无法读取私钥", "密码错误，或该文件不是有效的 PEM 私钥。")
                return
        except Exception:
            messagebox.showerror("无法读取私钥", "该文件不是有效的 PEM 私钥（.key / .pem）。")
            return
        cer_path = entry.get("cer_path") or ""
        if cer_path and Path(cer_path).is_file():
            cert = load_certificate_file(cer_path)
            if cert.public_key().public_numbers() != key.public_key().public_numbers():
                messagebox.showerror("私钥不匹配", "该私钥与档案中的证书不是一对，已拒绝登记。")
                return
        index = load_cert_index()
        for item in index:
            if item.get("id") == entry.get("id"):
                item["key_path"] = chosen
                break
        save_cert_index(index)
        self._refresh_cert_archive()
        self._select_cert_entry(entry.get("id", ""))
        self._cert_status(f"已登记私钥：{chosen}", "ok")

    def _cert_attach_p12(self, entry: dict) -> None:
        if not self._cert_ready():
            return
        chosen = filedialog.askopenfilename(
            title="选择已有的 P12 文件",
            filetypes=[("PKCS#12", "*.p12 *.pfx"), ("所有文件", "*.*")],
        )
        if not chosen:
            return
        password = self._ask_simple_password("导入 P12", "请输入该 P12 的导出密码：")
        if password is None:
            return
        try:
            key, cert, _chain = pkcs12.load_key_and_certificates(
                Path(chosen).read_bytes(), password.encode("utf-8"),
            )
        except Exception:
            messagebox.showerror("无法读取 P12", "密码错误，或该文件不是有效的 .p12。")
            return
        if cert is None or key is None:
            messagebox.showerror("P12 内容不完整", "该 P12 里没有同时包含证书和私钥。")
            return
        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            messagebox.showerror("P12 内容异常", "P12 中的证书与私钥不匹配。")
            return
        info = describe_certificate(cert)
        serial = str(entry.get("serial") or "").upper()
        if serial and serial != info["serial"].upper():
            messagebox.showerror(
                "证书不一致",
                f"该 P12 里的证书序列号是 {info['serial'][:16]}…，\n"
                f"与当前档案的 {serial[:16]}… 不同。\n\n"
                "请双击对应证书那一行的 P12 列。",
            )
            return
        index = load_cert_index()
        for item in index:
            if item.get("id") == entry.get("id"):
                item["p12_path"] = chosen
                item["serial"] = item.get("serial") or info["serial"]
                item["cn"] = item.get("cn") or info["cn"]
                if not item.get("not_after"):
                    item["not_after"] = info["not_after"].isoformat()
                    item["not_after_text"] = info["not_after_text"]
                    item["days_left"] = info["days_left"]
                if not (item.get("cer_path") and Path(item["cer_path"]).is_file()):
                    target = CERT_DIR / "imported" / f"{info['serial'][:16]}.cer"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(cert.public_bytes(serialization.Encoding.DER))
                    item["cer_path"] = str(target)
                break
        save_cert_index(index)
        self._refresh_cert_archive()
        self._select_cert_entry(entry.get("id", ""))
        self._cert_status(f"已登记 P12：{chosen}", "ok")

    def _ask_simple_password(self, title: str, prompt: str) -> str | None:
        px = self.px
        win = tk.Toplevel(self)
        win.title(title)
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)
        body = ttk.Frame(win, padding=px(18))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=prompt).grid(row=0, column=0, sticky="w")
        value = tk.StringVar()
        field = ttk.Entry(body, textvariable=value, show="*", width=34)
        field.grid(row=1, column=0, sticky="ew", pady=(px(8), px(12)))
        field.focus_set()
        result = {"value": None}

        def confirm() -> None:
            result["value"] = value.get()
            win.destroy()

        buttons = ttk.Frame(body)
        buttons.grid(row=2, column=0, sticky="e")
        ttk.Button(buttons, text="确定", command=confirm).pack(side="left")
        ttk.Button(buttons, text="取消", command=win.destroy).pack(side="left", padx=px(8))
        win.bind("<Return>", lambda _event: confirm())
        self.wait_window(win)
        return result["value"]

    def _selected_cert_entry(self) -> dict | None:
        selection = self.cert_tree.selection()
        if not selection:
            return None
        index = self.cert_tree.index(selection[0])
        if 0 <= index < len(self.cert_view):
            return self.cert_view[index]
        return None

    def _show_cert_detail(self) -> None:
        entry = self._selected_cert_entry()
        if not entry:
            return
        left_text = ""
        if entry.get("not_after"):
            try:
                left = days_left(datetime.fromisoformat(entry["not_after"]))
                left_text = f"（剩余 {left} 天）" if left > 0 else "（已过期）"
            except ValueError:
                left_text = ""
        lines = [
            f"名称：{entry.get('name', '')}",
            f"类型：{entry.get('type') or entry.get('cert_type', '')}",
            f"通用名称：{entry.get('cn') or '—'}",
            f"序列号：{entry.get('serial') or '—'}",
            f"有效期：{entry.get('not_after_text') or '—'}{left_text}",
            f"来源：{'Apple 同步' if entry.get('source') == 'apple' else '本工具申请/导入'}",
            "",
            "文件：",
        ]
        for label, key in (("私钥", "key_path"), ("CSR", "csr_path"), ("证书", "cer_path"), ("P12", "p12_path")):
            path = entry.get(key) or ""
            if (
                key == "key_path"
                and not (path and Path(path).is_file())
                and entry.get("p12_path")
                and Path(entry["p12_path"]).is_file()
            ):
                lines.append(f"  {label}：在 P12 内（导入时已验证）")
                continue
            state = "存在" if path and Path(path).is_file() else "缺失"
            lines.append(f"  {label}：{path or '—'}（{state}）")
        profiles = entry.get("profiles") or []
        lines.append("")
        lines.append(f"关联描述文件：{len(profiles)} 个")
        for item in profiles:
            lines.append(f"  · {item.get('name')}（{item.get('type')}，{item.get('expires_text')}）")
            lines.append(f"    {item.get('path')}")
        text = "\n".join(lines)
        self.cert_detail_text = text
        self.cert_detail.configure(state="normal")
        self.cert_detail.delete("1.0", "end")
        self.cert_detail.insert("1.0", text)
        self.cert_detail.configure(state="disabled")

    def _cert_reveal_selected(self) -> None:
        entry = self._selected_cert_entry()
        target = ""
        if entry:
            for key in ("p12_path", "cer_path", "key_path"):
                if entry.get(key) and Path(entry[key]).exists():
                    target = entry[key]
                    break
        if not target:
            CERT_DIR.mkdir(parents=True, exist_ok=True)
            target = str(CERT_DIR)
        subprocess.Popen(f'explorer /select,"{target}"')

    def _cert_copy_detail(self) -> None:
        if not self.cert_detail_text:
            return
        self.clipboard_clear()
        self.clipboard_append(self.cert_detail_text)
        self._cert_status("详情已复制到剪贴板", "ok")

    def _cert_open_dir(self) -> None:
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(CERT_DIR))

    def _cert_sync_certificates(self) -> None:
        if not self._cert_ready():
            return
        token = self._cert_api_token()
        if not token:
            return

        def task():
            items = list_remote_certificates(token)
            index = load_cert_index()
            added = 0
            for item in items:
                entry = None
                for candidate in index:
                    if candidate.get("apple_cert_id") == item["id"]:
                        entry = candidate
                        break
                if entry is None and item.get("serial"):
                    for candidate in index:
                        if str(candidate.get("serial") or "").upper() == item["serial"].upper():
                            entry = candidate
                            break
                if entry is None:
                    entry = {
                        "id": uuid.uuid4().hex,
                        "name": item["name"] or item["type"],
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "apple",
                        "profiles": [],
                    }
                    index.append(entry)
                    added += 1
                entry["apple_cert_id"] = item["id"]
                entry["type"] = cert_type_label(item["type"])
                entry["cert_type"] = item["type"]
                entry["serial"] = item["serial"]
                if item["expires"]:
                    entry["not_after"] = item["expires"].isoformat()
                    entry["not_after_text"] = fmt_when(item["expires"])
                    entry["days_left"] = days_left(item["expires"])
                if item.get("content") and not (entry.get("cer_path") and Path(entry["cer_path"]).is_file()):
                    try:
                        path = CERT_DIR / "apple" / f"{item['id']}.cer"
                        _write_cert_content(item["content"], path)
                        entry["cer_path"] = str(path)
                    except Exception:
                        pass
            save_cert_index(index)
            return added, len(items)

        def done(result) -> None:
            added, total = result
            self._refresh_cert_archive()
            self._cert_status(f"已同步 {total} 张证书（新增档案 {added}）", "ok")

        self._run_cert_task("正在从 Apple 同步证书…", task, done)

    def _cert_import_cer(self) -> None:
        if not self._cert_ready():
            return
        chosen = filedialog.askopenfilename(
            title="选择 Apple 签发的证书",
            filetypes=[("证书", "*.cer *.crt *.pem"), ("所有文件", "*.*")],
        )
        if not chosen:
            return
        try:
            info = describe_certificate(load_certificate_file(chosen))
        except Exception as exc:
            messagebox.showerror("无法读取证书", f"{exc}\n\n请确认选择的是 Apple 签发的 .cer 文件。")
            return
        target = filedialog.askopenfilename(
            title="选择与该证书配对的私钥（.key），可取消",
            filetypes=[("私钥", "*.key *.pem"), ("所有文件", "*.*")],
        )
        entry = {
            "id": uuid.uuid4().hex,
            "name": info["cn"] or Path(chosen).stem,
            "type": "导入证书",
            "cn": info["cn"],
            "serial": info["serial"],
            "not_after": info["not_after"].isoformat(),
            "not_after_text": info["not_after_text"],
            "days_left": info["days_left"],
            "cer_path": chosen,
            "key_path": target or "",
            "source": "manual",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "profiles": [],
        }
        index = load_cert_index()
        index.append(entry)
        save_cert_index(index)
        self._refresh_cert_archive()
        self._cert_status(f"已导入 {entry['name']}，可继续合成 P12", "ok")
        self._select_cert_entry(entry["id"])

    def _select_cert_entry(self, entry_id: str) -> None:
        for index, entry in enumerate(self.cert_view):
            if entry.get("id") == entry_id:
                children = self.cert_tree.get_children()
                if index < len(children):
                    self.cert_tree.selection_set(children[index])
                    self.cert_tree.see(children[index])
                break

    def _cert_export_p12(self) -> None:
        if not self._cert_ready():
            return
        entry = self._selected_cert_entry()
        if not entry:
            messagebox.showinfo("未选择证书", "请先在证书档案中选择一条记录。")
            return
        cer_path = entry.get("cer_path") or ""
        if not cer_path or not Path(cer_path).is_file():
            messagebox.showwarning("缺少证书文件", "这条档案没有可用的 .cer 文件，请先通过向导申请或导入证书。")
            return
        key_path = entry.get("key_path") or ""
        if not key_path or not Path(key_path).is_file():
            key_path = filedialog.askopenfilename(
                title="选择与该证书配对的私钥（.key）",
                filetypes=[("私钥", "*.key *.pem"), ("所有文件", "*.*")],
            )
            if not key_path:
                return
            entry["key_path"] = key_path
        password = self._ask_p12_password()
        if not password:
            return
        default_name = Path(cer_path).stem + ".p12"
        target = filedialog.asksaveasfilename(
            title="保存 P12",
            initialdir=str(Path(cer_path).parent),
            initialfile=default_name,
            defaultextension=".p12",
            filetypes=[("PKCS#12", "*.p12")],
        )
        if not target:
            return
        include_chain = messagebox.askyesno(
            "证书链",
            "是否附带 Apple 中间证书（推荐）？\n\n"
            "附带后部分工具导入更省事；下载失败会自动跳过，不影响 P12 生成。",
        )

        def task():
            chain = fetch_wwdr_chain(CERT_DIR / "chain") if include_chain else []
            return build_p12(cer_path, key_path, target, password, chain), chain

        def done(result) -> None:
            info, chain = result
            index = load_cert_index()
            for item in index:
                if item.get("id") == entry.get("id"):
                    item["p12_path"] = target
                    item["key_path"] = key_path
                    break
            save_cert_index(index)
            self._refresh_cert_archive()
            self._select_cert_entry(entry["id"])
            self._cert_status(f"P12 已生成：{target}", "ok")
            messagebox.showinfo(
                "P12 已生成",
                f"{target}\n\n大小 {human_size(info['size'])}，附带中间证书 {len(chain)} 张。\n"
                "在 HBuilderX 云打包的 iOS 签名里选择该文件并输入密码。",
            )

        self._run_cert_task("正在生成 P12…", task, done)

    def _cert_delete_entry(self) -> None:
        entry = self._selected_cert_entry()
        if not entry:
            messagebox.showinfo("未选择证书", "请先在证书档案中选择一条记录。")
            return
        if not messagebox.askyesno(
            "移除档案",
            f"从档案列表移除「{entry.get('name', '')}」？\n\n只移除记录，私钥/证书/P12 文件都会保留。",
        ):
            return
        index = [item for item in load_cert_index() if item.get("id") != entry.get("id")]
        save_cert_index(index)
        self._refresh_cert_archive()
        self.cert_detail.configure(state="normal")
        self.cert_detail.delete("1.0", "end")
        self.cert_detail.configure(state="disabled")
        self.cert_detail_text = ""
        self._cert_status("已移除档案记录", "muted")

    def _ask_p12_password(self) -> str | None:
        px = self.px
        win = tk.Toplevel(self)
        win.title("设置 P12 密码")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)
        body = ttk.Frame(win, padding=px(18))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="P12 密码（导入 HBuilderX 时需要，请自行记牢）：").grid(row=0, column=0, columnspan=2, sticky="w")
        first = tk.StringVar()
        second = tk.StringVar()
        ttk.Entry(body, textvariable=first, show="*", width=32).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(px(8), px(10)))
        ttk.Label(body, text="再次输入：").grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Entry(body, textvariable=second, show="*", width=32).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(px(8), px(12)))
        result = {"value": None}

        def confirm() -> None:
            value = first.get()
            if len(value) < 6:
                messagebox.showwarning("密码太短", "P12 密码至少 6 位。", parent=win)
                return
            if value != second.get():
                messagebox.showwarning("两次输入不一致", "请重新确认密码。", parent=win)
                return
            result["value"] = value
            win.destroy()

        buttons = ttk.Frame(body)
        buttons.grid(row=4, column=0, columnspan=2, sticky="e")
        ttk.Button(buttons, text="确定", command=confirm).pack(side="left")
        ttk.Button(buttons, text="取消", command=win.destroy).pack(side="left", padx=px(8))
        win.bind("<Return>", lambda _event: confirm())
        self.wait_window(win)
        return result["value"]

    # ------------------------------------------------------------ 描述文件

    def _fill_profile_tree(self, items: list[dict]) -> None:
        self.profile_view = items
        for row in self.prof_tree.get_children():
            self.prof_tree.delete(row)
        for item in items:
            left = None
            expires = item.get("expires")
            if expires is not None:
                left = days_left(expires)
            if item.get("source") == "本地":
                tag = "local"
            elif left is None:
                tag = ""
            elif left < 30:
                tag = "warn"
            else:
                tag = "ok"
            self.prof_tree.insert(
                "", "end",
                values=(
                    item.get("name", ""),
                    item.get("source", "Apple"),
                    profile_type_label(item.get("type", "")),
                    item.get("state") or "—",
                    item.get("expires_text") or fmt_when(expires) if expires else "—",
                    item.get("uuid", ""),
                ),
                tags=(tag,) if tag else (),
            )

    def _scan_local_profiles(self) -> list[dict]:
        items = []
        if not PROFILE_DIR.is_dir():
            return items
        for path in sorted(PROFILE_DIR.glob("*.mobileprovision")):
            try:
                info = parse_mobileprovision(str(path))
            except Exception:
                continue
            info["source"] = "本地"
            items.append(info)
        return items

    def _link_profile_to_archives(self, info: dict) -> int:
        serials = {str(value).upper() for value in info.get("cert_serials") or []}
        if not serials:
            return 0
        index = load_cert_index()
        linked = 0
        for entry in index:
            if str(entry.get("serial") or "").upper() in serials:
                profiles = [
                    item for item in entry.get("profiles") or []
                    if item.get("uuid") != info.get("uuid")
                ]
                profiles.append(
                    {
                        "path": info.get("path", ""),
                        "name": info.get("name", ""),
                        "uuid": info.get("uuid", ""),
                        "type": info.get("type", ""),
                        "expires_text": info.get("expires_text", ""),
                    }
                )
                entry["profiles"] = profiles
                linked += 1
        if linked:
            save_cert_index(index)
            self._refresh_cert_archive()
        return linked

    def _cert_refresh_profiles(self) -> None:
        if not self._cert_ready():
            return
        token = self._cert_api_token()
        if not token:
            return

        def task():
            return list_remote_profiles(token)

        def done(items) -> None:
            local = self._scan_local_profiles()
            known = {item.get("uuid") for item in items}
            merged = list(items)
            for item in local:
                if item.get("uuid") not in known:
                    item["source"] = "本地"
                    merged.append(item)
            for item in merged:
                item.setdefault("source", "Apple")
            self._fill_profile_tree(merged)
            self._cert_status(f"已读取 {len(items)} 个 Apple 描述文件，本地文件 {len(local)} 个", "ok")

        self._run_cert_task("正在读取描述文件列表…", task, done)

    def _cert_download_profiles(self) -> None:
        if not self._cert_ready():
            return
        selection = self.prof_tree.selection()
        if not selection:
            messagebox.showinfo("未选择描述文件", "请先在列表中选择要下载的描述文件。")
            return
        picked = []
        for row in selection:
            index = self.prof_tree.index(row)
            if 0 <= index < len(self.profile_view):
                picked.append(self.profile_view[index])
        remote = [item for item in picked if item.get("source", "Apple") != "本地" and item.get("id")]
        if not remote:
            messagebox.showinfo("无需下载", "选中的都是本地文件，已在描述文件目录中。")
            return
        token = self._cert_api_token()
        if not token:
            return

        def task():
            return [download_remote_profile(token, item["id"], PROFILE_DIR) for item in remote]

        def done(items) -> None:
            linked = sum(self._link_profile_to_archives(item) for item in items)
            self._cert_status(
                f"已下载 {len(items)} 个描述文件到 {PROFILE_DIR}" + (f"，关联 {linked} 个证书档案" if linked else ""),
                "ok",
            )
            local = self._scan_local_profiles()
            self._fill_profile_tree(local)
            messagebox.showinfo(
                "下载完成",
                f"已保存到：\n{PROFILE_DIR}\n\n"
                "在 HBuilderX 云打包的 iOS 描述文件里选择对应 .mobileprovision。",
            )

        self._run_cert_task("正在下载描述文件…", task, done)

    def _cert_import_profile(self) -> None:
        if not self._cert_ready():
            return
        chosen = filedialog.askopenfilename(
            title="选择 .mobileprovision 文件",
            filetypes=[("描述文件", "*.mobileprovision"), ("所有文件", "*.*")],
        )
        if not chosen:
            return
        try:
            info = parse_mobileprovision(chosen)
        except Exception as exc:
            messagebox.showerror("无法解析描述文件", str(exc))
            return
        PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^\w.\-]+", "_", info.get("name") or Path(chosen).stem)
        target = PROFILE_DIR / f"{safe_name}.mobileprovision"
        if Path(chosen).resolve() != target.resolve():
            shutil.copy2(chosen, target)
        info["path"] = str(target)
        info["source"] = "本地"
        self._link_profile_to_archives(info)
        local = self._scan_local_profiles()
        self._fill_profile_tree(local)
        self._cert_status(
            f"已导入 {info['name']}（{info['type']}，{info['expires_text']} 到期）", "ok",
        )

    def _cert_create_profile_dialog(self) -> None:
        if not self._cert_ready():
            return
        token = self._cert_api_token()
        if not token:
            return
        px = self.px
        win = tk.Toplevel(self)
        win.title("新建描述文件")
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)
        body = ttk.Frame(win, padding=px(16))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)

        ttk.Label(body, text="通过 App Store Connect API 创建，创建后自动下载到本地。").grid(
            row=0, column=0, sticky="w",
        )
        status = ttk.Label(body, text="正在读取 Apple 数据…", foreground=COLOR_MUTED)
        status.grid(row=1, column=0, sticky="w", pady=(px(6), px(10)))

        ttk.Label(body, text="名称").grid(row=2, column=0, sticky="w")
        name_var = tk.StringVar()
        ttk.Entry(body, textvariable=name_var).grid(row=3, column=0, sticky="ew", pady=(px(4), px(10)))

        ttk.Label(body, text="Bundle ID").grid(row=4, column=0, sticky="w")
        bundle_var = tk.StringVar()
        bundle_box = ttk.Combobox(body, textvariable=bundle_var, state="readonly", width=52)
        bundle_box.grid(row=5, column=0, sticky="ew", pady=(px(4), px(10)))

        ttk.Label(body, text="类型").grid(row=6, column=0, sticky="w")
        type_var = tk.StringVar(value=PROFILE_TYPE_CHOICES[0][0])
        ttk.Combobox(
            body, textvariable=type_var,
            values=[item[0] for item in PROFILE_TYPE_CHOICES], state="readonly", width=52,
        ).grid(row=7, column=0, sticky="ew", pady=(px(4), px(10)))

        lists = ttk.Frame(body)
        lists.grid(row=8, column=0, sticky="ew")
        lists.columnconfigure(0, weight=1)
        lists.columnconfigure(1, weight=1)
        ttk.Label(lists, text="选择证书（可多选）").grid(row=0, column=0, sticky="w")
        ttk.Label(lists, text="选择设备（Ad Hoc / Development）").grid(row=0, column=1, sticky="w", padx=(px(10), 0))
        cert_list = tk.Listbox(lists, selectmode="extended", height=7, exportselection=False)
        cert_list.grid(row=1, column=0, sticky="ew", pady=(px(4), 0))
        device_list = tk.Listbox(lists, selectmode="extended", height=7, exportselection=False)
        device_list.grid(row=1, column=1, sticky="ew", pady=(px(4), 0), padx=(px(10), 0))

        data = {"bundles": [], "certs": [], "devices": []}

        def apply_data() -> None:
            bundles = data["bundles"]
            bundle_box["values"] = [f"{item['identifier']}（{item['name']}）" for item in bundles]
            if bundles:
                bundle_box.current(0)
                name_var.set(f"{bundles[0]['identifier']} App Store")
            cert_list.delete(0, "end")
            for item in data["certs"]:
                cert_list.insert("end", f"{item['type']} · {item['name']} · {item['expires_text']}")
            device_list.delete(0, "end")
            for item in data["devices"]:
                device_list.insert("end", f"{item['name']} · {item['udid']}")
            status.configure(
                text=f"已读取 {len(bundles)} 个 Bundle ID、{len(data['certs'])} 张证书、{len(data['devices'])} 台设备",
                foreground=COLOR_OK,
            )

        def load_data() -> None:
            try:
                data["bundles"] = list_remote_bundle_ids(token)
                signing_types = {"DISTRIBUTION", "IOS_DISTRIBUTION", "IOS_DEVELOPMENT", "DEVELOPMENT"}
                data["certs"] = [
                    item for item in list_remote_certificates(token)
                    if item["type"] in signing_types
                ]
                data["devices"] = list_remote_devices(token)
            except Exception as exc:
                self.events.put(("cert_ui", lambda: status.configure(text=f"读取失败：{exc}", foreground=COLOR_ERR)))
                return
            self.events.put(("cert_ui", apply_data))

        threading.Thread(target=load_data, daemon=True).start()

        def create() -> None:
            if bundle_box.current() < 0:
                messagebox.showwarning("缺少参数", "请选择 Bundle ID。", parent=win)
                return
            name = name_var.get().strip()
            if not name:
                messagebox.showwarning("缺少参数", "请填写描述文件名称。", parent=win)
                return
            cert_ids = [data["certs"][index]["id"] for index in cert_list.curselection()]
            if not cert_ids:
                messagebox.showwarning("缺少参数", "请至少选择一张证书。", parent=win)
                return
            profile_label = type_var.get()
            profile_code = dict(PROFILE_TYPE_CHOICES)[profile_label]
            device_ids = []
            if profile_code in ("IOS_APP_ADHOC", "IOS_APP_DEVELOPMENT"):
                device_ids = [data["devices"][index]["id"] for index in device_list.curselection()]
                if not device_ids:
                    messagebox.showwarning("缺少参数", "Ad Hoc / Development 描述文件需要选择设备。", parent=win)
                    return
            if not messagebox.askyesno(
                "创建描述文件",
                f"将在 Apple 上创建「{name}」（{profile_label}）并下载到本地。\n确定继续吗？",
                parent=win,
            ):
                return
            bundle_id = data["bundles"][bundle_box.current()]["id"]
            win.destroy()

            def done(info) -> None:
                self._link_profile_to_archives(info)
                self._cert_status(f"描述文件已创建：{info.get('path', '')}", "ok")
                self._fill_profile_tree(self._scan_local_profiles())
                messagebox.showinfo(
                    "描述文件已创建",
                    f"{info.get('name', '')}\n{info.get('type', '')} · {info.get('expires_text', '')} 到期\n\n"
                    f"{info.get('path', '')}",
                )

            self._run_cert_task(
                "正在创建描述文件…",
                lambda: create_remote_profile(token, name, profile_code, bundle_id, cert_ids, device_ids),
                done,
            )

        buttons = ttk.Frame(body)
        buttons.grid(row=9, column=0, sticky="e", pady=(px(14), 0))
        ttk.Button(buttons, text="创建", command=create).pack(side="left")
        ttk.Button(buttons, text="关闭", command=win.destroy).pack(side="left", padx=px(8))

    def _open_cert_wizard(self) -> None:
        if not self._cert_ready():
            return
        CertWizard(self)

    # ------------------------------------------------------------ 状态与日志

    def _status(self, text: str, color: str = "muted") -> None:
        palette = {"ok": COLOR_OK, "err": COLOR_ERR, "muted": COLOR_MUTED, "info": COLOR_INFO}
        self.lbl_status.configure(text=text, foreground=palette.get(color, COLOR_MUTED))

    def _settings_status(self, text: str, color: str = "muted") -> None:
        palette = {"ok": COLOR_OK, "err": COLOR_ERR, "muted": COLOR_MUTED, "info": COLOR_INFO}
        self.lbl_settings_status.configure(text=text, foreground=palette.get(color, COLOR_MUTED))

    def _log_line(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        lines = int(self.log_text.index("end-1c").split(".")[0])
        if lines > 4000:
            self.log_text.delete("1.0", f"{lines - 4000}.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _set_progress(self, value: float | None) -> None:
        current = str(self.progress.cget("mode"))
        if value is None:
            if current != "indeterminate":
                self.progress.configure(mode="indeterminate")
                self.progress.start(12)
            return
        if current != "determinate":
            self.progress.stop()
            self.progress.configure(mode="determinate")
        self.progress["value"] = max(0.0, min(100.0, value))

    # ------------------------------------------------------------ 选择 IPA

    def pick_ipa(self) -> None:
        if self.uploading:
            return
        initial = self.cfg.get("default_ipa_dir") or str(Path.home() / "Downloads")
        chosen = filedialog.askopenfilename(
            title="选择 IPA 文件",
            initialdir=initial if Path(initial).exists() else str(Path.home()),
            filetypes=[("iOS 应用包", "*.ipa"), ("所有文件", "*.*")],
        )
        if not chosen:
            return
        self.current_ipa = chosen
        self.current_info = None
        self.lbl_ipa.configure(text=chosen)
        for var in self.info_vars.values():
            var.set("—")
        self._status("正在解析安装包…", "muted")
        threading.Thread(target=self._inspect_worker, args=(chosen,), daemon=True).start()

    def _inspect_worker(self, path: str) -> None:
        self.events.put(("ipa", inspect_ipa(path)))

    def _on_ipa(self, info: dict) -> None:
        self.current_info = info
        self.info_vars["bundle"].set(info["bundle_id"] or "—")
        self.info_vars["version"].set(info["version"] or "—")
        self.info_vars["build"].set(info["build"] or "—")
        self.info_vars["size"].set(human_size(info["size"]) if info["size"] else "—")
        if info["error"]:
            self._status("安装包解析失败：" + info["error"], "err")
        else:
            self._status(f"已选择 {info['name']}，可以开始上传", "muted")

    # ------------------------------------------------------------ 上传

    def _runtime_problem(self) -> str:
        cfg = self.cfg
        if not cfg.get("api_key_id") or not cfg.get("api_issuer"):
            return "API Key ID 或 Issuer ID 未填写"
        if not Path(cfg.get("api_key_path", "")).is_file():
            return ".p8 私钥文件不存在"
        return ""

    def start_upload(self) -> None:
        if self.uploading:
            return
        if not self.current_ipa or not Path(self.current_ipa).is_file():
            messagebox.showwarning("请选择文件", "请先选择一个 .ipa 文件。")
            return

        problem = self._runtime_problem()
        if problem:
            messagebox.showwarning("配置不完整", problem + "\n\n请到“设置”页补全并保存。")
            self.nb.select(self.tab_settings)
            return

        info = self.current_info or {}
        if not (info.get("version") and info.get("build")):
            info = inspect_ipa(self.current_ipa)
            self.current_info = info
            if not (info.get("version") and info.get("build")):
                messagebox.showerror(
                    "无法读取安装包信息",
                    "未能从 IPA 中解析出版本号和构建号。\n"
                    "Windows 上传必须提供这两项，请确认 IPA 文件完整后重试。",
                )
                return

        try:
            key_path = str(self._store_api_key(self.cfg))
        except Exception as exc:
            messagebox.showerror("准备失败", str(exc))
            return
        command_text = (
            "App Store Connect API · Build Upload · Key "
            + str(self.cfg.get("api_key_id") or "")
        )

        stamp = datetime.now()
        safe_name = re.sub(r"[^\w.\-]+", "_", Path(self.current_ipa).stem)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.last_log_path = LOG_DIR / f"{stamp:%Y%m%d-%H%M%S}_{safe_name}.log"
        self.last_error_line = ""

        self._clear_log()
        self._set_progress(None)
        self.uploading = True
        self.cancel_requested = False
        self.started_at = time.monotonic()
        self.btn_upload.configure(state="disabled")
        self.btn_cancel.configure(state="normal")
        self.btn_pick.configure(state="disabled")
        self._status("正在连接 App Store Connect…", "muted")
        self._log_line(f"$ {command_text}")
        self._log_line("")

        record = {
            "time": stamp.strftime("%Y-%m-%d %H:%M:%S"),
            "ipa_name": Path(self.current_ipa).name,
            "ipa_path": self.current_ipa,
            "size": info.get("size") or os.path.getsize(self.current_ipa),
            "version": info.get("version", ""),
            "build": info.get("build", ""),
            "bundle_id": info.get("bundle_id", ""),
            "success": False,
            "status": "失败",
            "exit_code": None,
            "duration": 0,
            "log": str(self.last_log_path),
            "command": command_text,
            "via": "api",
        }
        threading.Thread(
            target=self._api_upload_worker,
            args=(self.current_ipa, info, self.last_log_path, record, key_path),
            daemon=True,
        ).start()

    def _api_upload_worker(self, ipa_path: str, info: dict, log_path: Path, record: dict, key_path: str) -> None:
        return_code = 1
        try:
            with open(log_path, "w", encoding="utf-8", errors="replace") as log_file:
                def emit(text: str) -> None:
                    line = f"[{datetime.now():%H:%M:%S}] {text}"
                    log_file.write(line + "\n")
                    log_file.flush()
                    self.events.put(("line", line))

                def set_progress(value: float | None) -> None:
                    self.events.put(("progress", value))

                emit(f"使用 App Store Connect API 上传：{Path(ipa_path).name}")
                upload_build_via_api(
                    ipa_path=ipa_path,
                    info=info,
                    cfg=self.cfg,
                    key_path=key_path,
                    emit=emit,
                    set_progress=set_progress,
                    cancel_check=lambda: self.cancel_requested,
                )
                return_code = 0
        except UploadCanceled:
            self.events.put(("line", "已取消本次上传。"))
            return_code = -2
        except Exception as exc:
            self.events.put(("line", f"ERROR: {exc}"))
            return_code = 1
        self.events.put(("done", return_code, record))

    def _on_line(self, text: str) -> None:
        self._log_line(text)
        if "ERROR:" in text or "错误:" in text:
            self.last_error_line = text
        match = re.search(r"(\d{1,3}(?:\.\d+)?)\s*%", text)
        if match:
            try:
                value = float(match.group(1))
            except ValueError:
                value = -1
            if 0 <= value <= 100:
                self._set_progress(value)

    def _on_done(self, return_code: int, record: dict) -> None:
        self.uploading = False
        duration = time.monotonic() - self.started_at
        canceled = self.cancel_requested
        success = return_code == 0 and not canceled

        record["duration"] = duration
        record["exit_code"] = return_code
        record["success"] = success
        record["status"] = "已取消" if canceled else ("成功" if success else "失败")
        if not success and self.last_error_line:
            record["message"] = self.last_error_line

        self.btn_upload.configure(state="normal")
        self.btn_cancel.configure(state="disabled")
        self.btn_pick.configure(state="normal")

        if success:
            self._set_progress(100)
            self._status(f"上传成功（{human_duration(duration)}），Apple 已接收构建", "ok")
            self._log_line("")
            self._log_line("上传成功。App Store Connect 正在处理构建，可在 TestFlight 查看进度。")
            messagebox.showinfo(
                "上传成功",
                f"{record['ipa_name']} 已上传并通过 Apple 校验。\n\n"
                "构建处理通常需要 5–30 分钟，处理完成后即可在 TestFlight 中分发。",
            )
        elif canceled:
            self._set_progress(0)
            self._status("已取消本次上传", "muted")
            self._log_line("")
            self._log_line("用户取消了本次上传。")
        else:
            self._set_progress(0)
            detail = self.last_error_line or f"退出码 {return_code}"
            self._status(f"上传失败：{detail}", "err")
            self._log_line("")
            self._log_line(f"上传失败（退出码 {return_code}）。")
            messagebox.showerror(
                "上传失败",
                f"{detail}\n\n完整输出已保存到日志，可在历史记录中右键“查看日志”。",
            )

        self.history.append(record)
        save_history(self.history)
        self.refresh_history()

    def cancel_upload(self) -> None:
        if not self.uploading:
            return
        if not messagebox.askyesno("取消上传", "确定要中断本次上传吗？"):
            return
        self.cancel_requested = True
        self._status("正在取消…", "muted")

    # ------------------------------------------------------------ 历史

    def refresh_history(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.history_view = list(reversed(self.history))
        for record in self.history_view:
            version = record.get("version", "")
            build = record.get("build", "")
            version_text = f"{version}({build})" if version else "—"
            tag = "ok" if record.get("success") else ("cancel" if record.get("status") == "已取消" else "fail")
            self.tree.insert(
                "", "end",
                values=(
                    record.get("time", ""),
                    record.get("ipa_name", ""),
                    version_text,
                    human_size(record.get("size") or 0),
                    record.get("status", ""),
                    human_duration(record.get("duration") or 0),
                ),
                tags=(tag,),
            )

    def _selected_record(self) -> dict | None:
        selection = self.tree.selection()
        if not selection:
            return None
        index = self.tree.index(selection[0])
        if 0 <= index < len(self.history_view):
            return self.history_view[index]
        return None

    def open_selected_log(self) -> None:
        record = self._selected_record()
        if not record:
            messagebox.showinfo("未选择记录", "请先在历史记录中选择一条。")
            return
        log_path = Path(record.get("log", ""))
        if not log_path.is_file():
            messagebox.showwarning("日志不存在", f"日志文件已不存在：\n{log_path}")
            return
        try:
            os.startfile(str(log_path))
        except Exception as exc:
            messagebox.showerror("打开失败", str(exc))

    def reveal_selected_log(self) -> None:
        record = self._selected_record()
        if not record:
            messagebox.showinfo("未选择记录", "请先在历史记录中选择一条。")
            return
        log_path = Path(record.get("log", ""))
        target = log_path if log_path.exists() else Path(record.get("ipa_path", ""))
        if not target.exists():
            messagebox.showwarning("路径不存在", str(target))
            return
        subprocess.Popen(f'explorer /select,"{target}"')

    def copy_selected_command(self) -> None:
        record = self._selected_record()
        if not record:
            messagebox.showinfo("未选择记录", "请先在历史记录中选择一条。")
            return
        self.clipboard_clear()
        self.clipboard_append(record.get("command", ""))
        self._status("上传命令已复制到剪贴板", "muted")

    def delete_selected_record(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = self.tree.index(selection[0])
        if not messagebox.askyesno("删除记录", "只删除这条历史记录，日志文件会保留。确定吗？"):
            return
        record_index = len(self.history) - 1 - index
        if 0 <= record_index < len(self.history):
            del self.history[record_index]
        save_history(self.history)
        self.refresh_history()

    def clear_history(self) -> None:
        if not self.history:
            return
        if not messagebox.askyesno("清空历史", "确定清空全部上传历史吗？日志文件会保留。"):
            return
        self.history = []
        save_history(self.history)
        self.refresh_history()

    def open_log_dir(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(LOG_DIR))

    def _show_history_menu(self, event: tk.Event) -> None:
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        try:
            self.history_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.history_menu.grab_release()

    # ------------------------------------------------------------ 事件循环

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "line":
                    self._on_line(event[1])
                elif kind == "done":
                    self._on_done(event[1], event[2])
                elif kind == "ipa":
                    self._on_ipa(event[1])
                elif kind == "progress":
                    self._set_progress(event[1])
                elif kind == "cert_task":
                    _, callback, result, error = event
                    self.cert_busy = False
                    if error:
                        self._cert_status(error, "err")
                        messagebox.showerror("证书操作失败", error)
                    elif callback:
                        try:
                            callback(result)
                        except Exception as exc:
                            self._cert_status(str(exc), "err")
                            messagebox.showerror("证书操作失败", str(exc))
                elif kind == "cert_ui":
                    try:
                        event[1]()
                    except Exception:
                        pass
        except queue.Empty:
            pass
        if self.uploading and not self.cancel_requested:
            elapsed = time.monotonic() - self.started_at
            self._status(f"上传中… 已用时 {human_duration(elapsed)}", "muted")
        self.after(100, self._poll_events)

    def _on_close(self) -> None:
        if self.uploading:
            if not messagebox.askyesno("正在上传", "上传仍在进行，退出会中断上传。确定退出吗？"):
                return
        self.destroy()


class CertWizard(tk.Toplevel):
    """分步申请证书：密钥/CSR → Apple 签发 → 合成 P12，支持反复申请。"""

    STEPS = ("基本信息", "密钥与 CSR", "提交 Apple", "合成 P12", "完成")

    def __init__(self, app: "App"):
        super().__init__(app)
        self.app = app
        self.px = app.px
        self.title("新建证书申请")
        width, height = self.px(820), self.px(600)
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{width}x{height}+{(screen_w - width) // 2}+{(screen_h - height) // 2 - self.px(20)}")
        self.transient(app)
        self.grab_set()
        self.resizable(False, False)
        self.entry: dict | None = None

        self.name_var = tk.StringVar(value="IPA Distribution")
        self.type_var = tk.StringVar(value=CERT_TYPE_CHOICES[0][0])
        self.algo_var = tk.StringVar(value="RSA 2048")
        self.dir_var = tk.StringVar(value=str(CERT_DIR))
        self.mode_var = tk.StringVar(value="auto")
        self.source_var = tk.StringVar(value="new")
        self.pwd_var = tk.StringVar()
        self.pwd2_var = tk.StringVar()
        self.chain_var = tk.BooleanVar(value=True)
        self.cert_info_var = tk.StringVar(value="尚未获取证书")
        self.key_info_var = tk.StringVar(value="尚未生成密钥")
        self.p12_info_var = tk.StringVar(value="尚未生成 P12")

        self.reuse_cert_var = tk.StringVar()
        self.reuse_state_var = tk.StringVar(value="")
        self.reuse_name_var = tk.StringVar()
        self.reuse_bundle_var = tk.StringVar()
        self.reuse_type_var = tk.StringVar(value=PROFILE_TYPE_CHOICES[0][0])
        self.reuse_result_var = tk.StringVar(value="")
        self.reuse_dir_var = tk.StringVar(value=str(PROFILE_DIR))
        self.reuse_copy_p12_var = tk.BooleanVar(value=False)
        self.reuse_entries: list[dict] = []
        self.reuse_data = {"bundles": [], "certs": [], "devices": []}
        self.reuse_token: AscToken | None = None

        self.pos = 0
        self.seq = [0, 1, 2, 3, 4]
        self.header_texts = list(self.STEPS)

        self._build()
        self._show_pos(0)
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ------------------------------------------------------------ 布局

    def _build(self) -> None:
        px = self.px
        header = tk.Frame(self, bg=COLOR_HEADER, height=px(58))
        header.pack(fill="x")
        header.pack_propagate(False)
        self.step_cells = []
        for index, text in enumerate(self.STEPS):
            cell = tk.Frame(header, bg=COLOR_HEADER)
            cell.pack(side="left", padx=(px(18) if index == 0 else px(8), 0))
            badge = tk.Label(
                cell, text=str(index + 1), bg="#2f5c86", fg="white",
                font=("Segoe UI", 8, "bold"), width=2,
            )
            badge.pack(side="left")
            label = tk.Label(
                cell, text=text, bg=COLOR_HEADER, fg="#9fb6cf",
                font=(self.app.ui_family, 10),
            )
            label.pack(side="left", padx=(px(6), 0))
            self.step_cells.append((cell, badge, label))

        self.body = ttk.Frame(self, padding=px(18))
        self.body.pack(fill="both", expand=True)
        self.body.rowconfigure(0, weight=1)
        self.body.columnconfigure(0, weight=1)

        self.frames = [
            self._build_step1(),
            self._build_step2(),
            self._build_step3(),
            self._build_step4(),
            self._build_step5(),
            self._build_reuse_step(),
        ]
        for frame in self.frames:
            frame.grid(row=0, column=0, sticky="nsew")

        footer = ttk.Frame(self, padding=(px(18), 0, px(18), px(16)))
        footer.pack(fill="x")
        self.btn_back = ttk.Button(footer, text="上一步", command=self._go_back)
        self.btn_back.pack(side="left")
        self.btn_next = ttk.Button(footer, text="下一步", command=self._go_next)
        self.btn_next.pack(side="right")
        ttk.Button(footer, text="取消", command=self._close).pack(side="right", padx=px(8))

    def _build_step1(self) -> ttk.Frame:
        px = self.px
        frame = ttk.Frame(self.body)
        frame.columnconfigure(0, weight=1)

        source = ttk.LabelFrame(frame, text=" 证书来源 ", padding=(px(12), px(10)))
        source.grid(row=0, column=0, sticky="ew")
        ttk.Radiobutton(
            source, text="新建证书", variable=self.source_var, value="new",
            command=lambda: self._apply_mode("new"),
        ).pack(side="left")
        ttk.Radiobutton(
            source, text="使用已有证书（给另一个应用打包）", variable=self.source_var, value="existing",
            command=lambda: self._apply_mode("existing"),
        ).pack(side="left", padx=(px(16), 0))

        self.new_form = ttk.Frame(frame)
        self.new_form.grid(row=1, column=0, sticky="nsew", pady=(px(12), 0))
        self.new_form.columnconfigure(1, weight=1)

        self.existing_form = ttk.Frame(frame)
        self.existing_form.grid(row=1, column=0, sticky="nsew", pady=(px(12), 0))
        self.existing_form.columnconfigure(1, weight=1)
        self.existing_form.grid_remove()
        ttk.Label(self.existing_form, text="使用证书").grid(row=0, column=0, sticky="w")
        self.reuse_cert_box = ttk.Combobox(
            self.existing_form, textvariable=self.reuse_cert_var, state="readonly", width=56,
        )
        self.reuse_cert_box.grid(row=0, column=1, sticky="ew", padx=(px(10), 0))
        self.reuse_cert_box.bind("<<ComboboxSelected>>", lambda _event: self._on_reuse_cert_change())
        ttk.Label(
            self.existing_form, textvariable=self.reuse_state_var, style="Hint.TLabel",
            wraplength=px(680), justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(px(8), 0))
        self.reuse_p12_btn = ttk.Button(
            self.existing_form, text="生成 P12…", command=self._reuse_build_p12,
        )
        self.reuse_p12_btn.grid(row=2, column=0, sticky="w", pady=(px(8), 0))
        ttk.Label(
            self.existing_form,
            text="同一张证书可以给多个应用签名；换应用只需新建对应的描述文件，不用重新申请证书。",
            style="Hint.TLabel",
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(px(12), 0))

        ttk.Label(self.new_form, text="证书名称").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.new_form, textvariable=self.name_var).grid(row=0, column=1, sticky="ew", padx=(px(10), 0))

        ttk.Label(self.new_form, text="用途类型").grid(row=1, column=0, sticky="w", pady=(px(12), 0))
        ttk.Combobox(
            self.new_form, textvariable=self.type_var,
            values=[item[0] for item in CERT_TYPE_CHOICES], state="readonly",
        ).grid(row=1, column=1, sticky="ew", padx=(px(10), 0), pady=(px(12), 0))
        ttk.Label(
            self.new_form,
            text="HBuilderX 云打包签名选「Apple Distribution」或「iOS Distribution」；uni-push 用「Apple Push Services」。",
            style="Hint.TLabel",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(px(4), 0))

        ttk.Label(self.new_form, text="密钥算法").grid(row=3, column=0, sticky="w", pady=(px(12), 0))
        ttk.Combobox(
            self.new_form, textvariable=self.algo_var,
            values=["RSA 2048", "EC P-256"], state="readonly",
        ).grid(row=3, column=1, sticky="ew", padx=(px(10), 0), pady=(px(12), 0))

        ttk.Label(self.new_form, text="保存目录").grid(row=4, column=0, sticky="w", pady=(px(12), 0))
        dir_row = ttk.Frame(self.new_form)
        dir_row.grid(row=4, column=1, sticky="ew", padx=(px(10), 0), pady=(px(12), 0))
        dir_row.columnconfigure(0, weight=1)
        ttk.Entry(dir_row, textvariable=self.dir_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(
            dir_row, text="浏览…",
            command=lambda: self.app._browse_dir(self.dir_var),
        ).grid(row=0, column=1, padx=(px(8), 0))

        ttk.Separator(self.new_form).grid(row=5, column=0, columnspan=2, sticky="ew", pady=(px(16), px(10)))
        ttk.Label(
            self.new_form,
            text=(
                "流程：① 本地生成私钥与 CSR → ② Apple 用 CSR 签发证书 → ③ 本地把证书与私钥合成 .p12。\n"
                "私钥文件一旦丢失只能重新申请证书，请在同目录备份。"
            ),
            style="Hint.TLabel", justify="left",
        ).grid(row=6, column=0, columnspan=2, sticky="w")
        return frame

    def _build_reuse_step(self) -> ttk.Frame:
        px = self.px
        frame = ttk.Frame(self.body)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Bundle ID").grid(row=0, column=0, sticky="w")
        self.reuse_bundle_box = ttk.Combobox(frame, textvariable=self.reuse_bundle_var, state="readonly", width=54)
        self.reuse_bundle_box.grid(row=0, column=1, sticky="ew", padx=(px(10), 0))
        self.reuse_bundle_box.bind("<<ComboboxSelected>>", lambda _event: self._sync_reuse_name())

        ttk.Label(frame, text="类型").grid(row=1, column=0, sticky="w", pady=(px(8), 0))
        ttk.Combobox(
            frame, textvariable=self.reuse_type_var,
            values=[item[0] for item in PROFILE_TYPE_CHOICES], state="readonly",
        ).grid(row=1, column=1, sticky="ew", padx=(px(10), 0), pady=(px(8), 0))

        lists = ttk.Frame(frame)
        lists.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(px(12), 0))
        lists.columnconfigure(0, weight=1)
        lists.columnconfigure(1, weight=1)
        ttk.Label(lists, text="证书（可多选）").grid(row=0, column=0, sticky="w")
        ttk.Label(lists, text="设备（Ad Hoc / Development）").grid(row=0, column=1, sticky="w", padx=(px(10), 0))
        self.reuse_cert_list = tk.Listbox(lists, selectmode="extended", height=5, exportselection=False)
        self.reuse_cert_list.grid(row=1, column=0, sticky="ew", pady=(px(4), 0))
        self.reuse_device_list = tk.Listbox(lists, selectmode="extended", height=5, exportselection=False)
        self.reuse_device_list.grid(row=1, column=1, sticky="ew", padx=(px(10), 0), pady=(px(4), 0))

        ttk.Label(frame, text="保存目录").grid(row=3, column=0, sticky="w", pady=(px(10), 0))
        dir_row = ttk.Frame(frame)
        dir_row.grid(row=3, column=1, sticky="ew", padx=(px(10), 0), pady=(px(10), 0))
        dir_row.columnconfigure(0, weight=1)
        ttk.Entry(dir_row, textvariable=self.reuse_dir_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(
            dir_row, text="浏览…",
            command=lambda: self.app._browse_dir(self.reuse_dir_var),
        ).grid(row=0, column=1, padx=(px(8), 0))
        ttk.Checkbutton(
            frame, text="同时把 P12 复制到该目录（默认只放描述文件）",
            variable=self.reuse_copy_p12_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(px(6), 0))

        ttk.Label(frame, text="描述文件名称").grid(row=5, column=0, sticky="w", pady=(px(10), 0))
        ttk.Entry(frame, textvariable=self.reuse_name_var).grid(
            row=5, column=1, sticky="ew", padx=(px(10), 0), pady=(px(10), 0),
        )

        row = ttk.Frame(frame)
        row.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(px(12), 0))
        self.reuse_create_btn = ttk.Button(
            row, text="创建并下载描述文件", command=self._reuse_create, state="disabled",
        )
        self.reuse_create_btn.pack(side="left")
        ttk.Label(
            row, text="创建后自动保存，并给出 HBuilderX 该填的路径。", style="Hint.TLabel",
        ).pack(side="left", padx=(px(10), 0))

        ttk.Label(
            frame, textvariable=self.reuse_result_var, style="Value.TLabel",
            wraplength=px(740), justify="left",
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(px(10), 0))
        return frame

    def _build_step2(self) -> ttk.Frame:
        px = self.px
        frame = ttk.Frame(self.body)
        frame.columnconfigure(0, weight=1)
        ttk.Label(
            frame,
            text="在本机生成密钥对和证书签名请求（CSR）。这一步不联网，不会消耗 Apple 证书名额。",
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(frame, text="生成密钥与 CSR", command=self._generate_key).grid(
            row=1, column=0, sticky="w", pady=(px(12), 0),
        )
        ttk.Label(frame, textvariable=self.key_info_var, style="Value.TLabel", wraplength=px(720), justify="left").grid(
            row=2, column=0, sticky="w", pady=(px(14), 0),
        )
        ttk.Label(
            frame,
            text="生成后请立刻备份 .key 文件：Apple 只保存证书，私钥只存在这台电脑上。",
            style="Hint.TLabel",
        ).grid(row=3, column=0, sticky="w", pady=(px(10), 0))
        return frame

    def _build_step3(self) -> ttk.Frame:
        px = self.px
        frame = ttk.Frame(self.body)
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="选择获取证书的方式：").grid(row=0, column=0, sticky="w")

        auto = ttk.LabelFrame(frame, text=" 方式一：通过 API 自动申请（推荐） ", padding=(px(12), px(10)))
        auto.grid(row=1, column=0, sticky="ew", pady=(px(10), 0))
        auto.columnconfigure(0, weight=1)
        ttk.Label(
            auto,
            text="用「设置」页的 API Key 把 CSR 直接提交给 Apple，证书自动保存到本地。",
            style="Hint.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(auto, text="提交 CSR 并获取证书", command=self._submit_auto).grid(
            row=1, column=0, sticky="w", pady=(px(8), 0),
        )

        manual = ttk.LabelFrame(frame, text=" 方式二：在开发者网站手动申请 ", padding=(px(12), px(10)))
        manual.grid(row=2, column=0, sticky="ew", pady=(px(10), 0))
        manual.columnconfigure(0, weight=1)
        ttk.Label(
            manual,
            text=(
                "1. 打开 Apple 开发者网站 → Certificates → 点「+」\n"
                "2. 选择与上一步一致的证书类型，上传刚生成的 .csr 文件\n"
                "3. 下载签发的 .cer，回到这里导入"
            ),
            justify="left",
        ).grid(row=0, column=0, sticky="w")
        row = ttk.Frame(manual)
        row.grid(row=1, column=0, sticky="w", pady=(px(8), 0))
        ttk.Button(row, text="打开证书页面", command=lambda: webbrowser.open(PORTAL_CERT_URL)).pack(side="left")
        ttk.Button(row, text="选择已下载的 .cer…", command=self._choose_cer).pack(side="left", padx=px(8))

        ttk.Separator(frame).grid(row=3, column=0, sticky="ew", pady=(px(14), px(10)))
        ttk.Label(frame, text="当前证书：").grid(row=4, column=0, sticky="w")
        ttk.Label(
            frame, textvariable=self.cert_info_var, style="Value.TLabel",
            wraplength=px(720), justify="left",
        ).grid(row=5, column=0, sticky="w", pady=(px(4), 0))
        return frame

    def _build_step4(self) -> ttk.Frame:
        px = self.px
        frame = ttk.Frame(self.body)
        frame.columnconfigure(1, weight=1)

        ttk.Label(
            frame,
            text="把 Apple 签发的证书与本机私钥打包成 .p12，HBuilderX 云打包的 iOS 签名用它。",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, px(10)))

        ttk.Label(frame, text="P12 密码").grid(row=1, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.pwd_var, show="*").grid(row=1, column=1, sticky="ew", padx=(px(10), 0))
        ttk.Label(frame, text="再次输入").grid(row=2, column=0, sticky="w", pady=(px(8), 0))
        ttk.Entry(frame, textvariable=self.pwd2_var, show="*").grid(
            row=2, column=1, sticky="ew", padx=(px(10), 0), pady=(px(8), 0),
        )

        ttk.Checkbutton(
            frame, text="附带 Apple 中间证书（推荐，下载失败会自动跳过）",
            variable=self.chain_var,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(px(12), 0))

        ttk.Button(frame, text="生成 P12", command=self._build_p12).grid(
            row=4, column=0, sticky="w", pady=(px(14), 0),
        )
        ttk.Label(frame, textvariable=self.p12_info_var, style="Value.TLabel", wraplength=px(720), justify="left").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(px(12), 0),
        )
        return frame

    def _build_step5(self) -> ttk.Frame:
        px = self.px
        frame = ttk.Frame(self.body)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="证书已就绪", font=(self.app.ui_family, 14, "bold")).grid(row=0, column=0, sticky="w")
        self.summary_label = ttk.Label(frame, text="", justify="left", wraplength=px(730))
        self.summary_label.grid(row=1, column=0, sticky="w", pady=(px(12), 0))
        ttk.Label(
            frame,
            text=(
                "接着在 HBuilderX 云打包的 iOS 签名里选择这个 .p12 并输入密码；"
                "打包生成的 IPA 用「上传」页提交即可。"
            ),
            style="Hint.TLabel", justify="left", wraplength=px(730),
        ).grid(row=2, column=0, sticky="w", pady=(px(10), 0))
        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, sticky="w", pady=(px(16), 0))
        ttk.Button(buttons, text="打开证书目录", command=self._open_dir).pack(side="left")
        ttk.Button(buttons, text="再申请一张", command=self._restart).pack(side="left", padx=px(8))
        ttk.Button(buttons, text="由我继续申请描述文件", command=self._finish).pack(side="left")
        return frame

    # ------------------------------------------------------------ 步骤控制

    def _apply_mode(self, kind: str) -> None:
        self.source_var.set(kind)
        existing = kind == "existing"
        self.seq = [0, 5] if existing else [0, 1, 2, 3, 4]
        self.header_texts = ["选择证书", "为新应用打包"] if existing else list(self.STEPS)
        self._set_header(self.header_texts)
        if existing:
            self.new_form.grid_remove()
            self.existing_form.grid()
            self._refresh_reuse_certs()
        else:
            self.existing_form.grid_remove()
            self.new_form.grid()
        self._show_pos(0)

    def _set_header(self, texts: list[str]) -> None:
        px = self.px
        for cell, _badge, _label in self.step_cells:
            cell.pack_forget()
        for index, (cell, _badge, label) in enumerate(self.step_cells):
            if index >= len(texts):
                break
            cell.pack(side="left", padx=(px(18) if index == 0 else px(8), 0))
            label.configure(text=texts[index])

    def _show_pos(self, pos: int) -> None:
        self.pos = max(0, min(pos, len(self.seq) - 1))
        self.frames[self.seq[self.pos]].tkraise()
        for index, (_cell, badge, label) in enumerate(self.step_cells):
            if index >= len(self.header_texts):
                break
            active = index == self.pos
            done = index < self.pos
            badge.configure(bg="#1e7b34" if done else ("#2f5c86" if active else "#244a6d"))
            label.configure(fg="white" if active or done else "#9fb6cf")
        self._update_nav()

    def _update_nav(self) -> None:
        last = self.pos == len(self.seq) - 1
        self.btn_back.configure(state="normal" if self.pos > 0 else "disabled")
        self.btn_next.configure(text="完成" if last else "下一步", state="normal")
        if self.source_var.get() == "new" and last:
            self._update_summary()

    def _go_back(self) -> None:
        if self.pos > 0:
            self._show_pos(self.pos - 1)

    def _go_next(self) -> None:
        if self.pos == len(self.seq) - 1:
            self._close()
            return
        if self.source_var.get() == "existing":
            if self.pos == 0:
                entry = self._reuse_entry()
                if not entry:
                    messagebox.showwarning(
                        "没有可用证书", "证书档案里没有可直接复用的证书，请先新建或补充私钥/P12。", parent=self,
                    )
                    return
                p12 = entry.get("p12_path") or ""
                if not (p12 and Path(p12).is_file()):
                    messagebox.showwarning(
                        "缺少 P12",
                        "这张证书还没有可用的 P12，请先点「生成 P12…」生成后再继续。",
                        parent=self,
                    )
                    return
                self._show_pos(1)
                self._load_reuse_data()
            return

        if self.pos == 0:
            if not self.name_var.get().strip():
                messagebox.showwarning("缺少名称", "请填写证书名称。", parent=self)
                return
            directory = Path(self.dir_var.get().strip() or str(CERT_DIR))
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                messagebox.showerror("目录不可用", str(exc), parent=self)
                return
            self.dir_var.set(str(directory))
            if self.entry:
                self.entry["name"] = self.name_var.get().strip()
                self.entry["type"] = self.type_var.get()
                self.entry["cert_type"] = dict(
                    (label, code) for label, code, _hint in CERT_TYPE_CHOICES
                )[self.type_var.get()]
                index = load_cert_index()
                for item in index:
                    if item.get("id") == self.entry.get("id"):
                        item["name"] = self.entry["name"]
                        item["type"] = self.entry["type"]
                        item["cert_type"] = self.entry["cert_type"]
                        break
                save_cert_index(index)
                self.app._refresh_cert_archive()
        elif self.pos == 1:
            if not (self.entry and self.entry.get("key_path") and Path(self.entry["key_path"]).is_file()):
                messagebox.showwarning("尚未生成密钥", "请先在当前步骤生成密钥与 CSR。", parent=self)
                return
        elif self.pos == 2:
            if not (self.entry and self.entry.get("cer_path") and Path(self.entry["cer_path"]).is_file()):
                messagebox.showwarning(
                    "尚未获取证书",
                    "请用 API 申请，或在开发者网站申请后用「选择已下载的 .cer…」导入。",
                    parent=self,
                )
                return
        elif self.pos == 3:
            if not (self.entry and self.entry.get("p12_path") and Path(self.entry["p12_path"]).is_file()):
                messagebox.showwarning("尚未生成 P12", "请先在上一步生成 P12。", parent=self)
                return
        self._show_pos(self.pos + 1)

    # ------------------------------------------------------------ 复用已有证书

    def _refresh_reuse_certs(self) -> None:
        current = self._reuse_entry()
        entries = []
        for entry in load_cert_index():
            p12 = entry.get("p12_path") or ""
            cer = entry.get("cer_path") or ""
            key = entry.get("key_path") or ""
            if (p12 and Path(p12).is_file()) or (cer and Path(cer).is_file() and key and Path(key).is_file()):
                entries.append(entry)
        self.reuse_entries = list(reversed(entries))
        self.reuse_cert_box["values"] = [
            f"{item.get('name', '')} · {item.get('type', '')} · {item.get('not_after_text') or '—'}"
            for item in self.reuse_entries
        ]
        if not self.reuse_entries:
            self.reuse_cert_var.set("")
            self.reuse_state_var.set(
                "证书档案里没有可用于签名的证书：请先新建，或从 Apple 同步后补充私钥/P12。"
            )
            self.reuse_p12_btn.grid_remove()
            return
        target = 0
        if current:
            for index, item in enumerate(self.reuse_entries):
                if item.get("id") == current.get("id"):
                    target = index
                    break
        self.reuse_cert_box.current(target)
        self._on_reuse_cert_change()

    def _reuse_entry(self) -> dict | None:
        index = self.reuse_cert_box.current()
        if 0 <= index < len(self.reuse_entries):
            return self.reuse_entries[index]
        return None

    def _on_reuse_cert_change(self) -> None:
        entry = self._reuse_entry()
        if not entry:
            self.reuse_state_var.set("")
            self.reuse_p12_btn.grid_remove()
            return
        p12 = entry.get("p12_path") or ""
        if p12 and Path(p12).is_file():
            self.reuse_state_var.set(f"P12 已就绪：{p12}")
            self.reuse_p12_btn.grid_remove()
        else:
            self.reuse_state_var.set(
                f"该证书只有 .cer 与私钥，需要先生成 P12。证书到期：{entry.get('not_after_text') or '—'}"
            )
            self.reuse_p12_btn.grid()

    def _reuse_build_p12(self) -> None:
        entry = self._reuse_entry()
        if not entry:
            return
        cer_path = entry.get("cer_path") or ""
        key_path = entry.get("key_path") or ""
        if not (cer_path and Path(cer_path).is_file() and key_path and Path(key_path).is_file()):
            messagebox.showwarning("材料不全", "这张证书缺少 .cer 或私钥，无法生成 P12。", parent=self)
            return
        password = self.app._ask_p12_password()
        if not password:
            return
        default = Path(cer_path).with_suffix(".p12")
        target = filedialog.asksaveasfilename(
            parent=self, title="保存 P12",
            initialdir=str(default.parent), initialfile=default.name,
            defaultextension=".p12", filetypes=[("PKCS#12", "*.p12")],
        )
        if not target:
            return
        entry_id = entry.get("id")

        def task():
            chain = fetch_wwdr_chain(CERT_DIR / "chain")
            return build_p12(cer_path, key_path, target, password, chain), chain

        def done(result) -> None:
            info, chain = result
            index = load_cert_index()
            for item in index:
                if item.get("id") == entry_id:
                    item["p12_path"] = target
                    break
            save_cert_index(index)
            self.app._refresh_cert_archive()
            self._refresh_reuse_certs()
            self.reuse_state_var.set(f"P12 已生成：{target}（中间证书 {len(chain)} 张）")

        self.app._run_cert_task("正在生成 P12…", task, done)

    def _load_reuse_data(self) -> None:
        problem = self.app._runtime_problem()
        if problem:
            self.reuse_result_var.set(f"无法连接 Apple：{problem}，请先到「设置」页补全 API Key。")
            return
        try:
            token = token_from_config(self.app.cfg)
        except Exception as exc:
            self.reuse_result_var.set(str(exc))
            return
        self.reuse_token = token
        self.reuse_create_btn.configure(state="disabled")
        self.reuse_result_var.set("正在读取 Bundle ID、证书与设备…")

        def task():
            return (
                list_remote_bundle_ids(token),
                list_remote_certificates(token),
                list_remote_devices(token),
            )

        def done(result) -> None:
            bundles, certs, devices = result
            self.reuse_data = {"bundles": bundles, "certs": certs, "devices": devices}
            self.reuse_bundle_box["values"] = [
                f"{item['identifier']}（{item['name']}）" for item in bundles
            ]
            if bundles:
                self.reuse_bundle_box.current(0)
                self._sync_reuse_name()
            entry = self._reuse_entry() or {}
            serial = str(entry.get("serial") or "").upper()
            self.reuse_cert_list.delete(0, "end")
            for index, item in enumerate(certs):
                self.reuse_cert_list.insert(
                    "end", f"{item['type']} · {item['name']} · {item['expires_text']}"
                )
                if serial and item["serial"].upper() == serial:
                    self.reuse_cert_list.selection_set(index)
            self.reuse_device_list.delete(0, "end")
            for item in devices:
                self.reuse_device_list.insert("end", f"{item['name']} · {item['udid']}")
            self.reuse_create_btn.configure(state="normal")
            self.reuse_result_var.set(
                f"已读取 {len(bundles)} 个 Bundle ID、{len(certs)} 张证书、{len(devices)} 台设备。"
            )

        self.app._run_cert_task("正在读取 Apple 数据…", task, done)

    def _sync_reuse_name(self) -> None:
        index = self.reuse_bundle_box.current()
        bundles = self.reuse_data["bundles"]
        if 0 <= index < len(bundles):
            self.reuse_name_var.set(f"{bundles[index]['identifier']} App Store")

    def _reuse_create(self) -> None:
        entry = self._reuse_entry()
        if not entry:
            return
        bundle_index = self.reuse_bundle_box.current()
        if bundle_index < 0:
            messagebox.showwarning("缺少参数", "请选择 Bundle ID。", parent=self)
            return
        cert_ids = [
            self.reuse_data["certs"][index]["id"]
            for index in self.reuse_cert_list.curselection()
        ]
        if not cert_ids:
            messagebox.showwarning("缺少参数", "请至少选择一张证书。", parent=self)
            return
        profile_label = self.reuse_type_var.get()
        profile_code = dict(PROFILE_TYPE_CHOICES)[profile_label]
        device_ids = []
        if profile_code in ("IOS_APP_ADHOC", "IOS_APP_DEVELOPMENT"):
            device_ids = [
                self.reuse_data["devices"][index]["id"]
                for index in self.reuse_device_list.curselection()
            ]
            if not device_ids:
                messagebox.showwarning("缺少参数", "Ad Hoc / Development 需要选择设备。", parent=self)
                return
        bundle = self.reuse_data["bundles"][bundle_index]
        name = self.reuse_name_var.get().strip() or f"{bundle['identifier']} {profile_label}"
        if not messagebox.askyesno(
            "创建描述文件",
            f"将在 Apple 上创建「{name}」（{profile_label}），\n"
            f"Bundle ID：{bundle['identifier']}\n\n确定继续吗？",
            parent=self,
        ):
            return
        token = self.reuse_token or token_from_config(self.app.cfg)
        target_dir = Path(self.reuse_dir_var.get().strip() or str(PROFILE_DIR))
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("保存目录不可用", str(exc), parent=self)
            return
        copy_p12 = self.reuse_copy_p12_var.get()
        p12 = entry.get("p12_path") or ""

        def task():
            info = create_remote_profile(
                token, name, profile_code, bundle["id"], cert_ids, device_ids,
                out_dir=target_dir,
            )
            copied = ""
            if copy_p12 and p12 and Path(p12).is_file():
                destination = target_dir / Path(p12).name
                try:
                    shutil.copy2(p12, destination)
                    copied = str(destination)
                except Exception:
                    copied = ""
            return info, copied

        def done(result) -> None:
            info, copied = result
            self.app._link_profile_to_archives(info)
            lines = [f"描述文件已创建：{info.get('path', '')}"]
            if copied:
                lines.append(f"P12 已复制：{copied}")
            elif copy_p12:
                lines.append("P12 复制失败，请手动复制。")
            lines.extend(
                [
                    "",
                    "HBuilderX 云打包填写：",
                    f"  私钥证书：{copied or p12}",
                    f"  证书 profile 文件：{info.get('path', '')}",
                ]
            )
            self.reuse_result_var.set("\n".join(lines))

        self.app._run_cert_task("正在创建描述文件…", task, done)

    # ------------------------------------------------------------ 步骤 2

    def _generate_key(self) -> None:
        if self.entry and self.entry.get("key_path") and Path(self.entry["key_path"]).is_file():
            if not messagebox.askyesno(
                "重新生成密钥",
                "当前申请已有密钥。重新生成会让已申请的证书作废，确定吗？",
                parent=self,
            ):
                return
        name = self.name_var.get().strip()
        algorithm = "ec" if self.algo_var.get() == "EC P-256" else "rsa"
        directory = Path(self.dir_var.get().strip() or str(CERT_DIR))
        base = f"{re.sub(r'[^\w.\-]+', '_', name)}_{datetime.now():%Y%m%d-%H%M%S}"
        try:
            directory.mkdir(parents=True, exist_ok=True)
            key_pem, csr_pem = generate_key_and_csr(name, algorithm)
            key_path = directory / f"{base}.key"
            csr_path = directory / f"{base}.csr"
            key_path.write_bytes(key_pem)
            csr_path.write_bytes(csr_pem)
            try:
                os.chmod(key_path, 0o600)
            except Exception:
                pass
        except Exception as exc:
            messagebox.showerror("生成失败", str(exc), parent=self)
            return

        entry = {
            "id": (self.entry or {}).get("id") or uuid.uuid4().hex,
            "name": name,
            "type": self.type_var.get(),
            "cert_type": dict((label, code) for label, code, _ in CERT_TYPE_CHOICES)[self.type_var.get()],
            "algorithm": self.algo_var.get(),
            "cn": "",
            "serial": "",
            "not_after": "",
            "not_after_text": "",
            "apple_cert_id": "",
            "key_path": str(key_path),
            "csr_path": str(csr_path),
            "cer_path": "",
            "p12_path": "",
            "source": "tool",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "profiles": [],
        }
        if self.entry:
            entry["created_at"] = self.entry.get("created_at") or entry["created_at"]
        self.entry = entry
        index = load_cert_index()
        index = [item for item in index if item.get("id") != entry["id"]]
        index.append(entry)
        save_cert_index(index)
        self.app._refresh_cert_archive()

        self.key_info_var.set(
            f"私钥：{key_path}\nCSR：{csr_path}\n\n算法：{self.algo_var.get()}"
        )
        self.app._cert_status(f"已生成密钥与 CSR：{base}", "ok")

    # ------------------------------------------------------------ 步骤 3

    def _submit_auto(self) -> None:
        if not (self.entry and self.entry.get("csr_path") and Path(self.entry["csr_path"]).is_file()):
            messagebox.showwarning("尚未生成 CSR", "请先在上一步生成密钥与 CSR。", parent=self)
            return
        problem = self.app._runtime_problem()
        if problem:
            messagebox.showwarning(
                "API Key 不可用",
                problem + "\n\n请到「设置」页补全，或改用方式二在开发者网站申请。",
                parent=self,
            )
            return
        cert_type = self.entry.get("cert_type") or "IOS_DISTRIBUTION"
        if self.entry.get("cer_path") and Path(self.entry["cer_path"]).is_file():
            if not messagebox.askyesno(
                "已有证书",
                "当前申请已经获取过证书，继续会再申请一张并消耗名额。确定吗？",
                parent=self,
            ):
                return
        if not messagebox.askyesno(
            "确认申请",
            "将把 CSR 提交给 Apple 并申请一张新证书。\n\n"
            "注意：每种类型的证书名额有限（通常 2 张），申请会产生真实证书。\n确定继续吗？",
            parent=self,
        ):
            return
        token = token_from_config(self.app.cfg)
        csr_path = Path(self.entry["csr_path"])
        target = Path(self.entry["key_path"]).with_suffix(".cer")

        def done(result) -> None:
            try:
                _write_cert_content(result["content"], target)
            except Exception as exc:
                messagebox.showerror("保存证书失败", str(exc), parent=self)
                return
            self._adopt_certificate(target, result.get("id", ""))
            self.app._cert_status(f"Apple 已签发证书：{target.name}", "ok")
            messagebox.showinfo("证书已签发", f"已保存到：\n{target}", parent=self)

        self.app._run_cert_task(
            "正在向 Apple 申请证书…",
            lambda: create_remote_certificate(token, csr_path.read_bytes(), cert_type),
            done,
        )

    def _choose_cer(self) -> None:
        chosen = filedialog.askopenfilename(
            parent=self,
            title="选择从 Apple 下载的证书",
            filetypes=[("证书", "*.cer *.crt *.pem"), ("所有文件", "*.*")],
        )
        if not chosen:
            return
        if not (self.entry and self.entry.get("key_path")):
            messagebox.showwarning("尚未生成密钥", "请先在上一步生成密钥与 CSR。", parent=self)
            return
        target = Path(self.entry["key_path"]).with_suffix(".cer")
        try:
            shutil.copy2(chosen, target)
            self._adopt_certificate(target, "")
        except Exception as exc:
            messagebox.showerror("导入失败", str(exc), parent=self)

    def _adopt_certificate(self, path: Path, apple_cert_id: str = "") -> None:
        try:
            info = describe_certificate(load_certificate_file(str(path)))
        except Exception as exc:
            messagebox.showerror("无法读取证书", str(exc), parent=self)
            return
        entry = self.entry or {}
        entry.update(
            {
                "cer_path": str(path),
                "cn": info["cn"],
                "serial": info["serial"],
                "not_after": info["not_after"].isoformat(),
                "not_after_text": info["not_after_text"],
                "days_left": info["days_left"],
            }
        )
        if apple_cert_id:
            entry["apple_cert_id"] = apple_cert_id
        self.entry = entry
        index = load_cert_index()
        replaced = False
        for position, item in enumerate(index):
            if item.get("id") == entry.get("id"):
                index[position] = entry
                replaced = True
                break
        if not replaced:
            index.append(entry)
        save_cert_index(index)
        self.app._refresh_cert_archive()
        self.cert_info_var.set(
            f"{info['cn']}\n序列号 {info['serial']}\n有效期 {info['not_before_text']} → {info['not_after_text']}"
            f"（剩余 {info['days_left']} 天）\n签发者 {info['issuer']}"
        )

    # ------------------------------------------------------------ 步骤 4

    def _build_p12(self) -> None:
        if not (self.entry and self.entry.get("cer_path")):
            messagebox.showwarning("尚未获取证书", "请先完成上一步获取证书。", parent=self)
            return
        password = self.pwd_var.get()
        if len(password) < 6:
            messagebox.showwarning("密码太短", "P12 密码至少 6 位。", parent=self)
            return
        if password != self.pwd2_var.get():
            messagebox.showwarning("两次输入不一致", "请重新确认密码。", parent=self)
            return
        target = Path(self.entry["cer_path"]).with_suffix(".p12")
        if target.exists() and not messagebox.askyesno("覆盖文件", f"{target.name} 已存在，覆盖吗？", parent=self):
            return
        cer_path = self.entry["cer_path"]
        key_path = self.entry["key_path"]
        include_chain = self.chain_var.get()

        def task():
            chain = fetch_wwdr_chain(CERT_DIR / "chain") if include_chain else []
            return build_p12(cer_path, key_path, str(target), password, chain), chain

        def done(result) -> None:
            info, chain = result
            entry = dict(self.entry or {})
            entry["p12_path"] = str(target)
            self.entry = entry
            index = load_cert_index()
            for position, item in enumerate(index):
                if item.get("id") == entry.get("id"):
                    index[position] = entry
                    break
            else:
                index.append(entry)
            save_cert_index(index)
            self.app._refresh_cert_archive()
            self.p12_info_var.set(
                f"{target}\n大小 {human_size(info['size'])}，附带中间证书 {len(chain)} 张。\n"
                "密码请单独保存，丢失后只能重新合成。"
            )
            self.app._cert_status(f"P12 已生成：{target.name}", "ok")

        self.app._run_cert_task("正在生成 P12…", task, done)

    # ------------------------------------------------------------ 收尾

    def _update_summary(self) -> None:
        entry = self.entry or {}
        lines = [
            f"名称：{entry.get('name', '')}",
            f"类型：{entry.get('type', '')}",
            f"通用名称：{entry.get('cn') or '—'}",
            f"序列号：{entry.get('serial') or '—'}",
            f"有效期至：{entry.get('not_after_text') or '—'}（剩余 {entry.get('days_left', '—')} 天）",
            "",
            f"私钥：{entry.get('key_path') or '—'}",
            f"CSR：{entry.get('csr_path') or '—'}",
            f"证书：{entry.get('cer_path') or '—'}",
            f"P12：{entry.get('p12_path') or '—'}",
        ]
        self.summary_label.configure(text="\n".join(lines))

    def _open_dir(self) -> None:
        path = ""
        if self.entry:
            for key in ("p12_path", "cer_path", "key_path"):
                if self.entry.get(key) and Path(self.entry[key]).exists():
                    path = self.entry[key]
                    break
        if path:
            subprocess.Popen(f'explorer /select,"{path}"')
        else:
            CERT_DIR.mkdir(parents=True, exist_ok=True)
            os.startfile(str(CERT_DIR))

    def _restart(self) -> None:
        self.entry = None
        self.name_var.set("IPA Distribution")
        self.type_var.set(CERT_TYPE_CHOICES[0][0])
        self.algo_var.set("RSA 2048")
        self.pwd_var.set("")
        self.pwd2_var.set("")
        self.key_info_var.set("尚未生成密钥")
        self.cert_info_var.set("尚未获取证书")
        self.p12_info_var.set("尚未生成 P12")
        self.reuse_result_var.set("")
        self.reuse_copy_p12_var.set(False)
        self.reuse_cert_list.delete(0, "end")
        self.reuse_device_list.delete(0, "end")
        self.reuse_data = {"bundles": [], "certs": [], "devices": []}
        self.reuse_create_btn.configure(state="disabled")
        self._apply_mode("new")

    def _finish(self) -> None:
        self._close()
        self.app.nb.select(self.app.tab_cert)

    def _close(self) -> None:
        try:
            self.grab_release()
        except Exception:
            pass
        self.app._refresh_cert_archive()
        self.destroy()


def main() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    try:
        App().mainloop()
    except Exception:
        import traceback

        detail = traceback.format_exc()
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            (APP_DIR / "crash.log").write_text(detail, "utf-8")
        except Exception:
            pass
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("程序出错", detail[-2000:])
            root.destroy()
        except Exception:
            pass


if __name__ == "__main__":
    main()
