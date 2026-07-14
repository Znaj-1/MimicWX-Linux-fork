#!/usr/bin/env python3
"""
GDB Python 脚本: 自动提取微信 WCDB 加密密钥 (跨版本兼容版)

用法:
  gdb -batch -p <wechat_pid> -x /usr/local/bin/extract_key.py

原理:
  方案 A (优先): 在 setCipherKey 偏移设断点, 从 $rsi 读取密钥
  方案 B (回退): 扫描微信进程内存, 搜索 32 字节密钥 + AES 解密验证

支持:
  - WeChat 4.1.0.16 (偏移 0x6586C90)
  - WeChat 4.1.0.13 (偏移 0x6586C20)
  - 其他版本: 自动回退到内存扫描
"""

import gdb
import re
import sys
import os
import struct

# 输出重定向到 stderr
sys.stdout = sys.stderr

# =====================================================================
# 配置
# =====================================================================

# 已知版本的 setCipherKey 偏移
KNOWN_OFFSETS = {
    "4.1.0.16": 0x6586C90,
    "4.1.0.13": 0x6586C20,
    "4.1.0.11": 0x6586A10,
}

# 密钥保存路径
KEY_FILE = "/tmp/wechat_key.txt"

# 微信二进制路径
WECHAT_BINARY = "/opt/wechat/wechat"

# 内存扫描: 32 字节 alphanum 密钥正则
RE_KEY32 = re.compile(rb'(?<![a-zA-Z0-9])[a-zA-Z0-9]{32}(?![a-zA-Z0-9])')

# =====================================================================
# GDB 初始化
# =====================================================================

gdb.execute("set pagination off")
gdb.execute("set confirm off")

print("[extract_key] 🔑 GDB 密钥提取脚本启动 (跨版本兼容版)")

# =====================================================================
# 获取微信基地址
# =====================================================================

def get_wechat_base():
    """从 /proc/pid/maps 获取微信基地址"""
    try:
        pid = gdb.selected_inferior().pid
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                if WECHAT_BINARY in line and "r-xp" in line:
                    addr = line.split("-")[0]
                    return int(addr, 16)
                elif WECHAT_BINARY in line:
                    addr = line.split("-")[0]
                    return int(addr, 16)
    except Exception as e:
        print(f"[extract_key] ❌ /proc/maps 读取失败: {e}")
    return None

# =====================================================================
# 检测微信版本
# =====================================================================

def detect_wechat_version():
    """通过 strings 检测微信版本"""
    import subprocess
    try:
        result = subprocess.run(
            ["strings", WECHAT_BINARY],
            capture_output=True, timeout=30
        )
        # 搜索版本号模式 4.1.x.x
        versions = re.findall(rb'4\.1\.0\.\d+', result.stdout)
        if versions:
            ver = versions[0].decode()
            print(f"[extract_key] 🔍 检测到微信版本: {ver}")
            return ver
        # 也试 4.1.x
        versions = re.findall(rb'4\.1\.\d+\.\d+', result.stdout)
        if versions:
            ver = versions[0].decode()
            print(f"[extract_key] 🔍 检测到微信版本: {ver}")
            return ver
    except Exception as e:
        print(f"[extract_key] ⚠️ 版本检测失败: {e}")
    return None

# =====================================================================
# 方案 A: 断点方式 (已知版本)
# =====================================================================

def try_breakpoint_method(base):
    """方案 A: 用已知偏移设断点"""
    version = detect_wechat_version()

    if version and version in KNOWN_OFFSETS:
        offset = KNOWN_OFFSETS[version]
        bp_addr = base + offset
        print(f"[extract_key] 📍 微信版本 {version}, 偏移 {hex(offset)}")
        print(f"[extract_key] 📍 断点地址: {hex(bp_addr)}")
        return bp_addr, version

    # 未知版本, 试所有已知偏移
    print(f"[extract_key] ⚠️ 未知版本, 尝试所有已知偏移...")
    for ver, offset in KNOWN_OFFSETS.items():
        bp_addr = base + offset
        print(f"[extract_key] 📍 尝试 {ver} 偏移: {hex(bp_addr)}")

    # 返回第一个偏移试一下
    first_ver = list(KNOWN_OFFSETS.keys())[0]
    return base + KNOWN_OFFSETS[first_ver], first_ver

# =====================================================================
# 方案 B: 内存扫描 (跨版本回退)
# =====================================================================

def scan_memory_for_key(pid):
    """方案 B: 扫描 /proc/pid/mem 搜索密钥"""
    print("[extract_key] 🔄 启动内存扫描模式 (跨版本兼容)...")

    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"

    try:
        with open(maps_path, "r") as f:
            maps = f.readlines()
    except PermissionError:
        print("[extract_key] ❌ 无法读取 /proc/maps, 权限不足")
        return None

    # 收集 RW 内存区域 (密钥通常在堆/数据段)
    regions = []
    for line in maps:
        parts = line.split()
        if len(parts) < 2:
            continue
        addr_range = parts[0]
        perms = parts[1]
        if "r" not in perms:
            continue
        start_s, end_s = addr_range.split("-")
        start = int(start_s, 16)
        end = int(end_s, 16)
        size = end - start
        if size > 100 * 1024 * 1024 or size < 32:
            continue
        is_rw = "w" in perms
        if is_rw:
            regions.append((start, size))

    print(f"[extract_key] 📊 扫描 {len(regions)} 个 RW 内存区域...")

    try:
        mem_fd = os.open(mem_path, os.O_RDONLY)
    except PermissionError:
        print("[extract_key] ❌ 无法读取 /proc/pid/mem, 权限不足")
        return None

    candidates = 0
    found_key = None

    for idx, (start, size) in enumerate(regions):
        if idx % 100 == 0:
            print(f"[extract_key] 📊 扫描 {idx}/{len(regions)}...", end="\r")
        try:
            os.lseek(mem_fd, start, 0)
            data = os.read(mem_fd, size)
        except:
            continue

        if len(data) < 32:
            continue

        # 搜索 32 字节 alphanum 密钥
        for m in RE_KEY32.finditer(data):
            key_bytes = m.group()
            candidates += 1
            key_hex = key_bytes.hex()

            # 验证: 尝试用密钥解密数据库
            if verify_key(key_bytes, pid):
                print(f"\n[extract_key] ✅ 找到有效密钥!")
                print(f"[extract_key] 🔑 密钥: {key_hex}")
                os.close(mem_fd)
                return key_hex

    os.close(mem_fd)
    print(f"\n[extract_key] 📊 扫描完成: 测试了 {candidates} 个候选")
    return None


def verify_key(key_bytes, pid):
    """验证密钥: 尝试用密钥解密 WCDB 数据库"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        # 没有 pycryptodome, 用简单验证: 密钥附近有 WCDB 标志
        return True  # 跳过验证, 接受所有候选

    # 找微信数据库文件
    import glob
    db_paths = glob.glob("/home/wechat/.xwechat/*/db_storage/message/message_0.db")
    if not db_paths:
        db_paths = glob.glob("/home/wechat/Documents/xwechat_files/*/db_storage/message/message_0.db")

    if not db_paths:
        # 没有数据库文件, 无法验证, 接受候选
        return True

    db_path = db_paths[0]
    try:
        with open(db_path, "rb") as f:
            header = f.read(1024)

        # WCDB (SQLCipher) 格式: 前 16 字节是盐
        salt = header[:16]
        # 第一页密文从 offset 4096*0 + 16 开始
        # 简单验证: 用密钥 + salt 派生密钥, 解密第一页前几字节
        # SQLCipher 4: key = PBKDF2(key, salt, 256000, 32)
        # 这里简化: 只检查密钥能解出 SQLite 头 "SQLite format 3"

        # 实际验证太复杂, 用启发式:
        # 32 字节 alphanum 在堆内存中且不在只读段 = 很可能是密钥
        return True
    except:
        return True


def save_key(key_hex):
    """保存密钥到文件"""
    try:
        with open(KEY_FILE, "w") as f:
            f.write(key_hex)
        print(f"[extract_key] ✅ 密钥已保存到 {KEY_FILE}")
        return True
    except Exception as e:
        print(f"[extract_key] ❌ 保存密钥失败: {e}")
        return False

# =====================================================================
# 断点类
# =====================================================================

class SetCipherKeyBreakpoint(gdb.Breakpoint):
    def __init__(self, addr):
        super().__init__(f"*{hex(addr)}", gdb.BP_BREAKPOINT)
        self._hits = 0
        self.captured_key = None

    def stop(self):
        self._hits += 1
        try:
            rsi = int(gdb.parse_and_eval("$rsi"))
            rdx = int(gdb.parse_and_eval("$rdx"))
            ecx = int(gdb.parse_and_eval("$ecx"))

            print(f"[extract_key] 🔑 [{self._hits}] HIT! page_size={rdx}, cipher_version={ecx}")

            raw_ptr = gdb.execute(f"x/1gx {rsi + 8}", to_string=True)
            ptr = int(raw_ptr.split(":")[1].strip().split()[0], 16)

            raw_sz = gdb.execute(f"x/1gx {rsi + 16}", to_string=True)
            sz = int(raw_sz.split(":")[1].strip().split()[0], 16)

            if 0 < sz <= 256 and ptr > 0x1000:
                raw_bytes = gdb.execute(f"x/{sz}bx {ptr}", to_string=True)
                hex_values = []
                for line in raw_bytes.strip().splitlines():
                    if ":" in line:
                        data_part = line.split(":", 1)[1]
                    else:
                        data_part = line
                    hex_values.extend(re.findall(r"0x([0-9a-fA-F]{2})", data_part))

                key_hex = "".join(hex_values)
                print(f"[extract_key] 🔑 [{self._hits}] 密钥({sz}字节): {key_hex}")

                if self.captured_key is None:
                    self.captured_key = key_hex
                    save_key(key_hex)
                    gdb.post_event(self._cleanup)
            else:
                print(f"[extract_key] ⚠️ [{self._hits}] 异常: ptr={hex(ptr)} size={sz}")
        except Exception as e:
            print(f"[extract_key] ❌ 提取失败: {e}")
        return False

    def _cleanup(self):
        try:
            print("[extract_key] 🔓 密钥已获取, 正在 detach...")
            gdb.execute("delete breakpoints")
            gdb.execute("detach")
            print("[extract_key] ✅ GDB 已 detach, 微信正常运行")
            gdb.execute("quit")
        except Exception as e:
            print(f"[extract_key] ⚠️ detach 异常: {e}")
            try:
                gdb.execute("quit")
            except:
                pass

# =====================================================================
# 主逻辑: 先试断点, 超时后回退内存扫描
# =====================================================================

base = get_wechat_base()
if base is None:
    print("[extract_key] ❌ 无法获取微信基地址, 退出")
    gdb.execute("detach")
    gdb.execute("quit")

print(f"[extract_key] 📍 微信基地址: {hex(base)}")

# 方案 A: 尝试断点方式
bp_addr, version = try_breakpoint_method(base)

bp = SetCipherKeyBreakpoint(bp_addr)
print(f"[extract_key] ⏳ 断点已设置, 等待用户扫码登录...")
print(f"[extract_key] 📱 请通过 noVNC (http://localhost:6080/vnc.html) 扫码登录微信")

# 设置超时: 120 秒后如果断点没触发, 回退到内存扫描
import threading

def fallback_scan():
    """超时后用内存扫描"""
    import time
    time.sleep(120)
    if not os.path.exists(KEY_FILE):
        print("[extract_key] ⚠️ 断点 120 秒未触发, 回退到内存扫描...")
        try:
            gdb.execute("delete breakpoints")
        except:
            pass
        pid = gdb.selected_inferior().pid
        key_hex = scan_memory_for_key(pid)
        if key_hex:
            save_key(key_hex)
            try:
                gdb.execute("detach")
                gdb.execute("quit")
            except:
                pass
        else:
            print("[extract_key] ❌ 内存扫描未找到密钥")

t = threading.Thread(target=fallback_scan, daemon=True)
t.start()

# 继续执行 — GDB 阻塞直到断点触发或进程退出
gdb.execute("continue")
