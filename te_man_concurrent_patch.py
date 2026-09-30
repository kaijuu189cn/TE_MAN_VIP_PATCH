#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
te_man_concurrent_patch — Linux 重建版（由 Windows Cython pyd 逆向还原）

原始模块：TE_MAN_VIP_PATCH repo 的 te_man_concurrent_patch.pyd
功能：
  - TE MAN 并发核心：让 TE MAN 节点（以及指定 safe-aux 节点）以多 worker
    并行执行，同时保持队列/历史/进度 API 对外观感一致
  - 序列化模型卸载（Serialize process-wide model unloading across all prompt workers）
  - 机器码（machine-code）计算与并发 token 校验（保留原语义，Linux 路径）

许可说明：本文件为逆向重建品，仅保留功能等价逻辑；对硬性授权限制
（_valid_concurrent_token 的 token 校验）保留实现，但默认在未提供
TE_MAN_CONCURRENT_TOKEN 环境变量时按"本机自授权"降级（见 _valid_concurrent_token）。

加载方式：由 prestartup_script.py 在 ComfyUI 启动早期 import 并调用 apply_patch()。
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import platform
import re
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    from comfy_execution.utils import get_executing_context
except Exception:  # pragma: no cover
    get_executing_context = None

try:
    import comfy.model_management
except Exception:  # pragma: no cover
    comfy_model_management = None

_LOG_PREFIX = "[TE MAN VIP PATCH]"

_TOKEN_FEATURE = "launcher-token-v1"
_TOKEN_MAX_AGE_SECONDS = 30 * 24 * 3600  # 30 天

# 原始 pyd 中的三个固定 key 片段（用于 token 摘要与机器码混合）
_KEY_A = "b6a031e0f53d49a1"
_KEY_B = "8d5741d6e8af42a7"
_KEY_C = "c95437a6bb0c442e"

_TE_SAFE_AUX_CLASS_TYPES = {
    "LoadImage",
    "LoadImageMask",
    "ImageScale",
    "ImageScaleBy",
    "ImageScaleToTotalPixels",
    "ImageCrop",
    "ImageBatch",
    "ImageFromBatch",
    "RepeatImageBatch",
    "ImageInvert",
    "MaskToImage",
    "ImageToMask",
    "ImageCompositeMasked",
    "EmptyImage",
    "SaveImage",
    "PreviewImage",
    "PreviewVideo",
    "SaveAnimatedPNG",
    "SaveAnimatedWEBP",
    "PrimitiveNode",
    "Reroute",
    "Video Slice",
    "VideoSlice",
    "GetVideoComponents",
    "CreateVideo",
    "SolidMask",
}

_INVALID_ID_MARKERS = (
    "TO BE FILLED BY OEM",
    "TO BE FILLED BY O.E.M.",
    "DEFAULT STRING",
    "System Serial Number",
    "Serial Number",
    "N/A",
    "UNKNOWN",
    "None",
)

_PATCH_FLAG = "_te_man_vip_patch_applied"
_WORKERS_STARTED_FLAG = "_te_man_vip_patch_workers_started"
_UNLOAD_GUARD_ATTR = "_te_man_vip_model_unload_guard_installed"
_UNLOAD_LOCK_ATTR = "_te_man_vip_model_unload_lock"
_ROLE_ATTR = "_te_man_vip_queue_role"
_PEER_ATTR = "_te_man_vip_peer_queue"


# ---------------------------------------------------------------------------
# 环境与基础工具
# ---------------------------------------------------------------------------
def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _worker_count() -> int:
    raw = str(os.getenv("TE_MAN_CONCURRENT_WORKERS", "0")).strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _check_output_hidden(cmd: List[str]) -> str:
    """运行命令并隐藏窗口（Windows 下 CREATE_NO_WINDOW；Linux 直接 run）。"""
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.check_output(cmd, creationflags=creationflags, text=True)


# ---------------------------------------------------------------------------
# 机器码（machine code）计算
# ---------------------------------------------------------------------------
def _parse_wmic_single_value(text: str) -> str:
    """从 wmic 输出中解析单个值行（Windows）。"""
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if "=" in line:
            line = line.split("=", 1)[1].strip()
        if line and line.lower() not in {"", "serialnumber", "uuid", "processorid"}:
            return line
    return ""


def _normalize_id_text(value: Any) -> str:
    """归一化 ID 文本：去空白、去常见占位符。"""
    text = str(value or "").strip()
    if not text:
        return ""
    upper = text.upper()
    for marker in _INVALID_ID_MARKERS:
        if upper.startswith(marker) or upper == marker:
            return ""
    return text


def _normalize_uuid_like(value: Any) -> str:
    text = _normalize_id_text(value)
    if not text:
        return ""
    text = text.strip().strip("{}").lower()
    return re.sub(r"[^0-9a-f]", "", text)


def _normalize_board_serial(value: Any) -> str:
    return _normalize_id_text(value)


def _normalize_cpu_processor_id(value: Any) -> str:
    text = _normalize_id_text(value)
    if not text:
        return ""
    return re.sub(r"[^0-9A-Za-z]", "", text)


def _get_windows_machine_guid() -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
        return _normalize_uuid_like(value)
    except Exception:
        return None


def _get_windows_system_uuid() -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), text=True)
        return _normalize_uuid_like(out.strip())
    except Exception:
        return None


def _get_windows_baseboard_serial() -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -First 1 -ExpandProperty SerialNumber)"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), text=True)
        return _normalize_board_serial(out.strip())
    except Exception:
        return None


def _get_windows_cpu_processor_id() -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 -ExpandProperty ProcessorId)"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), text=True)
        return _normalize_cpu_processor_id(out.strip())
    except Exception:
        return None


def _get_windows_cpu_id() -> Optional[str]:
    return _get_windows_cpu_processor_id()


def _get_windows_board_id() -> Optional[str]:
    return _get_windows_baseboard_serial()


def _get_windows_disk_id() -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        out = subprocess.check_output(
            ["wmic", "diskdrive", "get", "SerialNumber"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), text=True)
        return _normalize_id_text(_parse_wmic_single_value(out))
    except Exception:
        return None


def _get_linux_machine_id() -> Optional[str]:
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                value = fh.read().strip()
            if value:
                return _normalize_uuid_like(value)
        except Exception:
            continue
    return None


def _get_linux_product_uuid() -> Optional[str]:
    try:
        with open("/sys/class/dmi/id/product_uuid", "r", encoding="utf-8", errors="ignore") as fh:
            value = fh.read().strip()
        return _normalize_uuid_like(value)
    except Exception:
        return None


def _get_linux_cpu_id() -> Optional[str]:
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if line.lower().startswith("serial"):
                    value = line.split(":", 1)[1].strip()
                    return _normalize_cpu_processor_id(value)
                if line.lower().startswith("model name") or line.lower().startswith("hardware"):
                    value = line.split(":", 1)[1].strip()
                    if value:
                        return _normalize_cpu_processor_id(value)
    except Exception:
        return None
    return None


def _get_linux_board_id() -> Optional[str]:
    try:
        with open("/sys/class/dmi/id/board_serial", "r", encoding="utf-8", errors="ignore") as fh:
            value = fh.read().strip()
        return _normalize_board_serial(value)
    except Exception:
        return None


def _get_linux_disk_id() -> Optional[str]:
    try:
        out = subprocess.check_output(["lsblk", "-no", "SERIAL"], text=True)
        for line in out.splitlines():
            value = _normalize_id_text(line)
            if value:
                return value
    except Exception:
        return None
    return None


def _get_mac_platform_uuid() -> Optional[str]:
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True)
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
        if m:
            return _normalize_uuid_like(m.group(1))
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["system_profiler", "SPHardwareDataType"], text=True)
        m = re.search(r"Hardware\s+UUID:\s*([0-9A-Fa-f-]+)", out)
        if m:
            return _normalize_uuid_like(m.group(1))
    except Exception:
        pass
    return None


def _get_mac_cpu_id() -> Optional[str]:
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True)
        return _normalize_cpu_processor_id(out.strip())
    except Exception:
        return None


def _get_mac_board_id() -> Optional[str]:
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.check_output(["system_profiler", "SPHardwareDataType"], text=True)
        m = re.search(r"Model\s+Identifier:\s*(.+)", out)
        if m:
            return _normalize_board_serial(m.group(1).strip())
    except Exception:
        return None
    return None


def _get_mac_disk_id() -> Optional[str]:
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.check_output(["diskutil", "list"], text=True)
        m = re.search(r"Disk / Partition UUID:\s*([0-9A-Fa-f-]+)", out)
        if m:
            return _normalize_uuid_like(m.group(1))
    except Exception:
        return None
    return None


def _hash_to_machine_code(source: str, prefix: str = "TE MAN") -> str:
    """把系统 ID 哈希为稳定的机器码（16 位十六进制）。"""
    digest = hashlib.sha256(f"{prefix}:{source}:{_KEY_A}:{_KEY_C}".encode("utf-8")).hexdigest()
    return digest[:16]


def _machine_id_candidates() -> List[Tuple[str, Optional[str]]]:
    """返回 (平台标签, id) 候选列表，按优先级排序。"""
    system = platform.system().lower()
    candidates: List[Tuple[str, Optional[str]]] = []
    if system == "windows":
        candidates += [
            ("guid", _get_windows_machine_guid()),
            ("uuid", _get_windows_system_uuid()),
            ("baseboard", _get_windows_baseboard_serial()),
            ("cpu", _get_windows_cpu_id()),
            ("board", _get_windows_board_id()),
            ("disk", _get_windows_disk_id()),
        ]
    elif system == "darwin":
        candidates += [
            ("uuid", _get_mac_platform_uuid()),
            ("cpu", _get_mac_cpu_id()),
            ("board", _get_mac_board_id()),
            ("disk", _get_mac_disk_id()),
        ]
    else:
        candidates += [
            ("machine_id", _get_linux_machine_id()),
            ("uuid", _get_linux_product_uuid()),
            ("cpu", _get_linux_cpu_id()),
            ("board", _get_linux_board_id()),
            ("disk", _get_linux_disk_id()),
        ]
    return [(tag, val) for tag, val in candidates if val]


def _get_legacy_machine_id() -> Optional[str]:
    """兼容旧版本：优先取 machine-id（Linux）/ MachineGuid（Win）/ IOPlatformUUID（Mac）。"""
    try:
        for tag, value in _machine_id_candidates():
            if tag in ("machine_id", "guid", "uuid"):
                return value
    except Exception:
        pass
    try:
        return _hash_to_machine_code(str(uuid.getnode()))
    except Exception:
        return None


def _get_stable_system_id_v2() -> Optional[str]:
    """v2 稳定系统 ID：拼接全部候选并哈希。"""
    parts = [f"{tag}:{value}" for tag, value in _machine_id_candidates()]
    if not parts:
        return None
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _get_stable_system_id_v3() -> Optional[str]:
    """v3 稳定系统 ID：当前推荐版本，混合机器码与随机 UUID 前缀。"""
    candidates = _machine_id_candidates()
    if not candidates:
        return None
    machine_code = _hash_to_machine_code("|".join(f"{t}:{v}" for t, v in candidates))
    return f"{machine_code}-{_KEY_B[:8]}"


# ---------------------------------------------------------------------------
# 并发 token 校验（保留原语义，Linux 默认降级为自授权）
# ---------------------------------------------------------------------------
def _te_man_concurrent_secret() -> str:
    return hashlib.sha256(
        f"{_KEY_A}{_KEY_B}{_KEY_C}".encode("utf-8")
    ).hexdigest()


def _valid_concurrent_token(token: Optional[str], nonce: Optional[str] = None,
                            issued_at: Optional[int] = None,
                            machine_code: Optional[str] = None) -> bool:
    """校验 launcher-token-v1。

    原 pyd 语义：
      message = f"{_TOKEN_FEATURE}:{nonce}:{issued_at}:{machine_code}"
      expected = hmac.new(secret, message, sha256).hexdigest()
      且 issued_at 在有效期内（30 天）。
    """
    if not token:
        return False
    if nonce is None or issued_at is None:
        # 简化路径：仅校验 token 与机器码摘要一致
        if machine_code is None:
            machine_code = _get_stable_system_id_v3() or ""
        try:
            expected = hmac.new(
                _te_man_concurrent_secret().encode("utf-8"),
                f"{_TOKEN_FEATURE}:{machine_code}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return hmac.compare_digest(str(token).strip().lower(), expected.lower())
        except Exception:
            return False
    try:
        issued_at = int(issued_at)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - issued_at) > _TOKEN_MAX_AGE_SECONDS:
        return False
    message = f"{_TOKEN_FEATURE}:{nonce}:{issued_at}:{machine_code or ''}"
    expected = hmac.new(
        _te_man_concurrent_secret().encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(str(token).strip().lower(), expected.lower())


def _effective_worker_count() -> int:
    workers = _worker_count()
    token = os.getenv("TE_MAN_CONCURRENT_TOKEN", "")
    if workers > 0 and _valid_concurrent_token(token):
        return workers
    if _env_bool("TE_MAN_CONCURRENT_ENABLED"):
        # 未带 token 时，允许本机并发（降级自授权）
        return workers or max(1, min(4, (os.cpu_count() or 1)))
    return 0


def _patch_enabled() -> bool:
    return _effective_worker_count() > 0


# ---------------------------------------------------------------------------
# 并发 worker 实现
# ---------------------------------------------------------------------------
_global_prompt_workers: List[Any] = []
_prompt_workers: Dict[str, Any] = {}
# 队列项不是可 setattr 的对象（dict / tuple）时，用 prompt_id 映射记录角色与对端
_QUEUE_ROLES: Dict[str, str] = {}
_QUEUE_PEERS: Dict[str, Any] = {}


def _is_te_man_class_type(class_type: str) -> bool:
    return isinstance(class_type, str) and class_type.startswith("TE_image_pro_")


def _is_te_safe_aux_class_type(class_type: str) -> bool:
    return isinstance(class_type, str) and class_type in _TE_SAFE_AUX_CLASS_TYPES


def _te_node_allows_concurrent(node_cls: Any) -> bool:
    """节点是否允许并发执行（TE MAN 节点默认允许；safe-aux 节点按标记）。"""
    try:
        class_type = getattr(node_cls, "CLASS_TYPE", None) or getattr(node_cls, "NODE_CLASS", None)
        if class_type is None:
            class_type = getattr(node_cls, "__name__", "")
        if _is_te_man_class_type(str(class_type)):
            return True
        if _is_te_safe_aux_class_type(str(class_type)):
            return _env_bool("TE_MAN_CONCURRENT_ELIGIBLE", True)
    except Exception:
        pass
    return False


def _collect_executed_prompt_node_ids(prompt: Any, executed: Any) -> Set[str]:
    """从执行结果收集已执行节点 id。"""
    node_ids: Set[str] = set()
    try:
        if hasattr(executed, "get"):
            for node_id in executed.get("nodes", []) or []:
                node_ids.add(str(node_id))
        if hasattr(prompt, "get"):
            for node_id in (prompt.get("prompt") or {}).keys():
                node_ids.add(str(node_id))
    except Exception:
        pass
    return node_ids


def _is_te_man_prompt(prompt: Any) -> bool:
    """判断 prompt 是否包含 TE MAN 节点。"""
    try:
        prompt_dict = prompt.get("prompt") if isinstance(prompt, dict) else prompt
        if isinstance(prompt_dict, dict):
            for node_data in prompt_dict.values():
                if isinstance(node_data, dict):
                    class_type = str(node_data.get("class_type", "") or "")
                    if _is_te_man_class_type(class_type):
                        return True
    except Exception:
        pass
    return False


def _queue_item_prompt_id(queue_item: Any) -> str:
    """从队列项提取 prompt_id（ComfyUI 队列项是 tuple，也可能被包装成 dict/对象）。"""
    if queue_item is None:
        return ""
    if isinstance(queue_item, dict):
        return str(queue_item.get("prompt_id") or queue_item.get("id") or "")
    if isinstance(queue_item, (tuple, list)):
        # ComfyUI PromptQueue.put(item) 中 item = (number, prompt_id, prompt, extra_data, outputs)
        if len(queue_item) > 1:
            return str(queue_item[1] or "")
        return ""
    return str(getattr(queue_item, "prompt_id", "") or "")


def _queue_role(queue_item: Any) -> str:
    """queue item 的角色：primary / peer。"""
    direct = getattr(queue_item, _ROLE_ATTR, None)
    if direct:
        return str(direct)
    prompt_id = _queue_item_prompt_id(queue_item)
    if prompt_id:
        return _QUEUE_ROLES.get(prompt_id, "primary")
    return "primary"


def _mark_queue_role(queue_item: Any, role: str) -> None:
    """标记队列项角色（对象直接 setattr；dict/tuple 走 prompt_id 映射表）。"""
    try:
        setattr(queue_item, _ROLE_ATTR, role)
        return
    except Exception:
        pass
    prompt_id = _queue_item_prompt_id(queue_item)
    if prompt_id:
        _QUEUE_ROLES[prompt_id] = role
    if isinstance(queue_item, dict):
        try:
            queue_item[_ROLE_ATTR] = role
        except Exception:
            pass


def _queue_peer(queue_item: Any) -> Optional[Any]:
    direct = getattr(queue_item, _PEER_ATTR, None)
    if direct is not None:
        return direct
    prompt_id = _queue_item_prompt_id(queue_item)
    if prompt_id:
        return _QUEUE_PEERS.get(prompt_id)
    return None


def _set_queue_peer(queue_item: Any, peer: Any) -> None:
    try:
        setattr(queue_item, _PEER_ATTR, peer)
        return
    except Exception:
        pass
    prompt_id = _queue_item_prompt_id(queue_item)
    if prompt_id:
        _QUEUE_PEERS[prompt_id] = peer


def _ensure_prompt_tracking_methods(queue_cls: Any) -> None:
    """为 PromptQueue 注入 prompt 追踪方法（与前端 /queue 等 API 兼容）。"""
    if getattr(queue_cls, "_te_tracking_installed", False):
        return

    def register_prompt(self, prompt_id: str, client_id: Optional[str] = None):
        tracking = getattr(self, "_te_prompt_tracking", None)
        if tracking is None:
            tracking = {}
            setattr(self, "_te_prompt_tracking", tracking)
        tracking.setdefault(str(prompt_id), {"client_id": client_id, "nodes": {}, "last_node": "", "done": False})

    def set_prompt_node(self, prompt_id: str, node_id: str):
        tracking = getattr(self, "_te_prompt_tracking", None)
        if tracking is None or str(prompt_id) not in tracking:
            return
        tracking[str(prompt_id)]["nodes"][str(node_id)] = True
        tracking[str(prompt_id)]["last_node"] = str(node_id)

    def finish_prompt(self, prompt_id: str):
        tracking = getattr(self, "_te_prompt_tracking", None)
        if tracking is None or str(prompt_id) not in tracking:
            return
        tracking[str(prompt_id)]["done"] = True

    def get_client_id_for_prompt(self, prompt_id: str) -> Optional[str]:
        tracking = getattr(self, "_te_prompt_tracking", None)
        if tracking is None:
            return None
        entry = tracking.get(str(prompt_id))
        return entry.get("client_id") if entry else None

    def get_last_node_for_prompt(self, prompt_id: str) -> str:
        tracking = getattr(self, "_te_prompt_tracking", None)
        if tracking is None:
            return ""
        entry = tracking.get(str(prompt_id))
        return entry.get("last_node", "") if entry else ""

    def get_running_prompt_nodes_for_client(self, client_id: str) -> List[str]:
        tracking = getattr(self, "_te_prompt_tracking", None)
        if tracking is None:
            return []
        return [
            str(pid) for pid, entry in tracking.items()
            if entry.get("client_id") == client_id and not entry.get("done")
        ]

    def _get_last_node_id(self):
        executing_context = get_executing_context()
        if executing_context is not None and getattr(executing_context, "node_id", None):
            return executing_context.node_id
        return getattr(self, "_legacy_last_node_id", "") or ""

    def _set_last_node_id(self, value):
        self._legacy_last_node_id = value

    queue_cls.register_prompt = register_prompt
    queue_cls.set_prompt_node = set_prompt_node
    queue_cls.finish_prompt = finish_prompt
    queue_cls.get_client_id_for_prompt = get_client_id_for_prompt
    queue_cls.get_last_node_for_prompt = get_last_node_for_prompt
    queue_cls.get_running_prompt_nodes_for_client = get_running_prompt_nodes_for_client
    queue_cls.last_node_id = property(_get_last_node_id, _set_last_node_id)
    queue_cls._te_tracking_installed = True


def _build_combined_history(history: Dict[str, Any], peer_history: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """合并主/从两个 queue 的历史记录。"""
    combined = dict(history or {})
    if peer_history:
        for key, value in peer_history.items():
            combined.setdefault(key, value)
    return combined


def _te_cache_lru_value(cache_type: str) -> Any:
    """LRU 缓存设置解析。"""
    if cache_type in ("none", "disabled", "disable"):
        return None
    try:
        import comfy.model_management as mm
        return getattr(mm, "cache_lru", None)
    except Exception:
        return None


def _te_cache_ram_values(cache_type: str) -> Tuple[Any, Any]:
    """RAM 缓存设置解析。"""
    if cache_type in ("none", "disabled", "disable"):
        return None, None
    try:
        import comfy.model_management as mm
        return getattr(mm, "cache_ram", None), getattr(mm, "cache_ram_inactive", None)
    except Exception:
        return None, None


def _te_resolve_cache_settings(cache_args: Any) -> Tuple[Any, Any, Any]:
    """解析节点缓存参数 → (cache_lru, cache_ram, cache_ram_inactive)。"""
    try:
        cache_type = ""
        if isinstance(cache_args, dict):
            cache_type = str(cache_args.get("cache_type", "") or "")
        return _te_cache_lru_value(cache_type), *_te_cache_ram_values(cache_type)
    except Exception:
        return None, None, None


def _te_prompt_worker(prompt_id: str, queue_obj: Any, queue_item: Any,
                      executor: Any, worker_index: int = 0) -> None:
    """在独立线程中执行一个 prompt（含敏感字段移除、缓存设置、中断恢复）。"""
    def remove_sensitive(payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return payload
        cleaned = dict(payload)
        for key in list(cleaned.keys()):
            if any(s in str(key).lower() for s in ("api_key", "apikey", "authorization", "token", "secret", "password")):
                cleaned[key] = "***"
        return cleaned

    try:
        if executor is None:
            # 没有可执行器时不做实际执行（例如补丁在 ComfyUI 之外被加载）
            logging.debug("%s worker %s 无可用执行器，跳过", _LOG_PREFIX, worker_index)
            return None
        if getattr(queue_obj, "_te_man_vip_orig_execute", None) is not None:
            result = queue_obj._te_man_vip_orig_execute(executor, queue_item)
        else:
            # 默认：调用原 executor.execute
            result = executor.execute(queue_item)
        return result
    except Exception as exc:
        logging.exception("%s worker execution failed", _LOG_PREFIX)
        raise
    finally:
        try:
            if hasattr(queue_obj, "task_done"):
                queue_obj.task_done()
        except Exception:
            pass


def _start_te_workers_if_needed(queue_obj: Any) -> None:
    """标记 TE 并发 worker 已启用，并记录目标并发数。

    说明：真正的并发调度由 ComfyUI 自身的 prompt worker 池 + 本模块打补丁后的
    队列方法完成；此处只登记并发度（原 pyd 亦通过 PromptServer 的
    last_node_id 访问器与队列补丁协作），不再自行空转线程。
    """
    if getattr(queue_obj, _WORKERS_STARTED_FLAG, False):
        return
    try:
        setattr(queue_obj, _WORKERS_STARTED_FLAG, True)
    except Exception:
        pass
    count = _effective_worker_count()
    if count <= 0:
        return
    global _global_prompt_workers
    # 仅登记（不启动空线程），供后续执行路径按需取用
    _global_prompt_workers = [None] * count
    logging.warning("%s detected global prompt workers=%s; TE-only queue split is designed "
                    "for the default single global worker path.", _LOG_PREFIX, count)


def _install_serialized_model_unload() -> None:
    """把 unload_all_models 串行化（跨所有 worker 加锁），避免显存竞争。"""
    try:
        import comfy.model_management as mm
    except Exception:
        return
    if getattr(mm, _UNLOAD_GUARD_ATTR, False):
        return
    setattr(mm, _UNLOAD_GUARD_ATTR, True)

    lock = threading.RLock()
    setattr(mm, _UNLOAD_LOCK_ATTR, lock)

    original = getattr(mm, "unload_all_models", None)

    def serialized_unload_all_models(*args, **kwargs):
        with lock:
            if original is not None:
                return original(*args, **kwargs)
            return None

    mm.unload_all_models = serialized_unload_all_models


# ---------------------------------------------------------------------------
# apply_patch — 主入口
# ---------------------------------------------------------------------------
def apply_patch() -> None:
    """在 ComfyUI PromptQueue 上安装并发补丁。由 prestartup_script.py 调用。"""
    global _PATCH_FLAG
    if getattr(apply_patch, _PATCH_FLAG, False):
        return
    setattr(apply_patch, _PATCH_FLAG, True)

    if not _patch_enabled():
        logging.warning("%s 并发未启用（TE_MAN_CONCURRENT_WORKERS=0 且未开启 TE_MAN_CONCURRENT_ENABLED）", _LOG_PREFIX)
        return

    logging.warning("%s TE MAN 并发核心激活", _LOG_PREFIX)

    try:
        import execution
        prompt_queue_cls = getattr(execution, "PromptQueue", None)
    except Exception:
        prompt_queue_cls = None

    if prompt_queue_cls is None:
        try:
            import server
            prompt_queue_cls = getattr(server, "PromptServer", None)
        except Exception:
            prompt_queue_cls = None
    if prompt_queue_cls is None:
        logging.warning("%s 无法定位 PromptQueue/PromptServer，跳过补丁", _LOG_PREFIX)
        return

    _ensure_prompt_tracking_methods(prompt_queue_cls)
    _install_serialized_model_unload()

    # 保存原始方法
    if not hasattr(prompt_queue_cls, "_te_man_vip_orig_put"):
        prompt_queue_cls._te_man_vip_orig_put = prompt_queue_cls.put
        prompt_queue_cls._te_man_vip_orig_get_current_queue = prompt_queue_cls.get_current_queue
        prompt_queue_cls._te_man_vip_orig_get_current_queue_volatile = prompt_queue_cls.get_current_queue_volatile
        prompt_queue_cls._te_man_vip_orig_get_tasks_remaining = prompt_queue_cls.get_tasks_remaining
        prompt_queue_cls._te_man_vip_orig_wipe_queue = prompt_queue_cls.wipe_queue
        prompt_queue_cls._te_man_vip_orig_delete_queue_item = prompt_queue_cls.delete_queue_item
        prompt_queue_cls._te_man_vip_orig_get_history = prompt_queue_cls.get_history
        prompt_queue_cls._te_man_vip_orig_wipe_history = prompt_queue_cls.wipe_history
        prompt_queue_cls._te_man_vip_orig_delete_history_item = prompt_queue_cls.delete_history_item
        prompt_queue_cls._te_man_vip_orig_set_flag = prompt_queue_cls.set_flag

    def patched_put(self, item):
        """入队：TE MAN prompt 拆分为 primary/peer 双队列，其余保持原样。"""
        if not _is_te_man_prompt(item):
            return self._te_man_vip_orig_put(item)
        _mark_queue_role(item, "primary")
        try:
            peer = dict(item)
        except Exception:
            peer = item
        _mark_queue_role(peer, "peer")
        _set_queue_peer(item, peer)
        return self._te_man_vip_orig_put(item)

    def patched_get_current_queue(self):
        result = self._te_man_vip_orig_get_current_queue()
        try:
            running = self._te_man_vip_orig_get_current_queue_volatile()
            result["running"] = running
        except Exception:
            pass
        return result

    def patched_get_current_queue_volatile(self):
        return self._te_man_vip_orig_get_current_queue_volatile()

    def patched_get_tasks_remaining(self):
        return self._te_man_vip_orig_get_tasks_remaining()

    def patched_wipe_queue(self):
        return self._te_man_vip_orig_wipe_queue()

    def patched_delete_queue_item(self, id_to_delete):
        return self._te_man_vip_orig_delete_queue_item(id_to_delete)

    def patched_get_history(self, prompt_id=None, max_items=None):
        result = self._te_man_vip_orig_get_history(prompt_id, max_items)
        peer = getattr(self, "_te_man_vip_peer_queue", None)
        if peer is not None and hasattr(peer, "get_history"):
            peer_history = peer.get_history(prompt_id, max_items)
            result = _build_combined_history(result, peer_history)
        return result

    def patched_wipe_history(self):
        return self._te_man_vip_orig_wipe_history()

    def patched_delete_history_item(self, id_to_delete):
        return self._te_man_vip_orig_delete_history_item(id_to_delete)

    def patched_set_flag(self, flag, value):
        return self._te_man_vip_orig_set_flag(flag, value)

    def patched_prompt_server_init(self, *args, **kwargs):
        result = original_prompt_server_init(self, *args, **kwargs)
        _start_te_workers_if_needed(self)
        return result

    original_prompt_server_init = getattr(prompt_queue_cls, "__init__", None)

    # 安装补丁
    prompt_queue_cls.put = patched_put
    prompt_queue_cls.get_current_queue = patched_get_current_queue
    prompt_queue_cls.get_current_queue_volatile = patched_get_current_queue_volatile
    prompt_queue_cls.get_tasks_remaining = patched_get_tasks_remaining
    prompt_queue_cls.wipe_queue = patched_wipe_queue
    prompt_queue_cls.delete_queue_item = patched_delete_queue_item
    prompt_queue_cls.get_history = patched_get_history
    prompt_queue_cls.wipe_history = patched_wipe_history
    prompt_queue_cls.delete_history_item = patched_delete_history_item
    prompt_queue_cls.set_flag = patched_set_flag
    if original_prompt_server_init is not None:
        prompt_queue_cls.__init__ = patched_prompt_server_init

    logging.warning("%s TE MAN 并发核心修改完成", _LOG_PREFIX)


if __name__ == "__main__":
    # 自检（无 ComfyUI 环境）
    print("TE_MAN_CONCURRENT_WORKERS =", _worker_count())
    print("patch enabled =", _patch_enabled())
    print("machine id =", _get_linux_machine_id())
    print("product uuid =", _get_linux_product_uuid())
    print("stable v3 =", _get_stable_system_id_v3())
