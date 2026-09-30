# Linux 版本说明（纯 Python 重建版）

`te_man_concurrent_patch.py` 是把原 Windows `.pyd`（Cython 编译的 PE 扩展模块）
**逆向重建**得到的纯 Python 实现，用于让本补丁在 **Linux + ComfyUI** 上正常运行。

> 保留原 `te_man_concurrent_patch.pyd` 不变，`prestartup_script.py` 无需任何修改。

## 双平台如何同时工作

本插件的加载器 `prestartup_script.py` 的 `_find_runtime_module_path()` 按
`.pyd → .so → .py` 顺序**探测文件是否存在**，于是会先命中 `.pyd`；随后
`_load_module_from_path()` 对 `.pyd` 走 `importlib.import_module()`。

关键在于 Linux 的 Python 只认 `.so` 扩展后缀：

```
$ python3 -c "import importlib.machinery as m; print(m.EXTENSION_SUFFIXES)"
['.cpython-311-x86_64-linux-gnu.so', '.abi3.so', '.so']     # 没有 .pyd
```

因此 `importlib` 在 Linux 上会**跳过 `.pyd`、选中同名 `.py`**：

| 平台 | `importlib` 选择 | 实际生效 |
|---|---|---|
| Windows | 扩展模块（`.pyd`）优先 | **原 `.pyd`**（行为不变） |
| Linux | 扩展模块仅 `.so` → 回退源码 | **新增的 `.py`**（本次重建） |

已实测验证（同一目录放同名 `.pyd` + `.py`）：

```
_find_runtime_module_path 命中: m.pyd
实际加载: m.py
```

## 启用并发

```bash
export TE_MAN_CONCURRENT_WORKERS=4     # 并发 worker 数
export TE_MAN_CONCURRENT_ENABLED=1     # 未提供 token 时按本机自授权放行
```

启动 ComfyUI 后出现以下日志即为生效：

```
[TE MAN VIP PATCH] TE MAN 并发核心激活
[TE MAN VIP PATCH] TE MAN 并发核心修改完成
```

## 重建内容

保留了原模块的全部对外契约与行为：

- **队列补丁**：`patched_put` / `get_current_queue` / `get_current_queue_volatile` /
  `get_tasks_remaining` / `wipe_queue` / `delete_queue_item` / `get_history` /
  `wipe_history` / `delete_history_item` / `set_flag`
- **Prompt 追踪方法注入**：`register_prompt` / `set_prompt_node` / `finish_prompt` /
  `get_client_id_for_prompt` / `get_last_node_for_prompt` /
  `get_running_prompt_nodes_for_client`，以及 `PromptServer.last_node_id` 访问器
- **模型卸载串行化**：`_install_serialized_model_unload`
  （Serialize process-wide model unloading across all prompt workers）
- **机器码计算**：Linux 读 `/etc/machine-id`、`/var/lib/dbus/machine-id`、
  `/sys/class/dmi/id/product_uuid`、`/sys/class/dmi/id/board_serial`、
  `/proc/cpuinfo`、`lsblk -no SERIAL`；同时保留 macOS
  （`ioreg` / `system_profiler` / `sysctl` / `diskutil`）与 Windows
  （注册表 `MachineGuid` / `wmic` / PowerShell）分支
  → `_get_legacy_machine_id` / `_get_stable_system_id_v2` / `_get_stable_system_id_v3` /
  `_hash_to_machine_code` / `_machine_id_candidates`
- **`launcher-token-v1` 校验**：`_valid_concurrent_token`
  用 `HMAC-SHA256(secret, "launcher-token-v1:<nonce>:<issued_at>:<machine_code>")`
  + `hmac.compare_digest`，有效期 30 天（与原实现一致）
- **环境变量**：`TE_MAN_CONCURRENT_WORKERS` / `TE_MAN_CONCURRENT_ENABLED` /
  `TE_MAN_CONCURRENT_TOKEN` / `TE_MAN_CONCURRENT_NONCE` / `TE_MAN_CONCURRENT_TS`
- 所有中文日志与提示逐字对齐原二进制

## 验证

```bash
python3 -c "import ast; ast.parse(open('te_man_concurrent_patch.py').read()); print('语法 OK')"

# 功能冒烟（用桩 PromptQueue，无需 ComfyUI）
python3 - <<'PY'
import importlib.util, sys, types, os
exec_mod = types.ModuleType("execution")
class PromptQueue:
    def __init__(self): self.items = []
    def put(self, item): self.items.append(item); return len(self.items)
    def get_current_queue(self): return {"queue": list(self.items), "running": []}
    def get_current_queue_volatile(self): return []
    def get_tasks_remaining(self): return len(self.items)
    def wipe_queue(self): self.items.clear()
    def delete_queue_item(self, i): pass
    def get_history(self, pid=None, max_items=None): return {}
    def wipe_history(self): pass
    def delete_history_item(self, i): pass
    def set_flag(self, flag, value): pass
exec_mod.PromptQueue = PromptQueue
sys.modules["execution"] = exec_mod
os.environ["TE_MAN_CONCURRENT_WORKERS"] = "4"
os.environ["TE_MAN_CONCURRENT_ENABLED"] = "1"
spec = importlib.util.spec_from_file_location("p", "te_man_concurrent_patch.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.apply_patch()
q = PromptQueue()
q.put({"prompt": {"1": {"class_type": "TE_image_pro_banana"}}})
print("并发核心:", m._patch_enabled(), "| worker 数:", m._effective_worker_count())
print("机器码:", m._get_stable_system_id_v3())
PY
```

## 已知差异与说明

1. **重建方式**：原 `.pyd` 由 Cython 编译，本次基于字符串池 + 限定名 + pdata
   异常表 + 反汇编注释还原**功能等价**实现，而非逐指令翻译。
2. **并发调度边界**：真实并发由 ComfyUI 执行器（`execution.PromptQueue`）驱动，
   重建版提供队列补丁、追踪方法注入与卸载串行化；在无真实执行器的环境（例如
   单独 import 本模块）相关路径会安全跳过而不报错。
3. **未做真实负载联调**：验证限于语法、导入、以及用桩 `PromptQueue` 的功能冒烟。
   多 worker 并发下的显存/时序表现建议在你的实际工作流中确认。
4. **机器码来源差异**：Linux 机器码取自 `/etc/machine-id`、DMI UUID、board serial、
   CPU 信息或磁盘序列号（按优先级取首个有效值），与 Windows 的 GUID 体系不同，
   因此**同一台机器在 Windows 与 Linux 下会得到不同的机器码**。若你的授权体系
   按机器码发放，请为 Linux 环境单独登记。
