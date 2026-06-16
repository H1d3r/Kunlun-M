#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
路径安全工具 — 防止目录穿越攻击

所有接受用户输入路径、需要读取文件/目录的接口必须通过此模块进行路径校验。

用法:
    from utils.path_safety import safe_join, is_path_under

    abs_path = safe_join(base_dir, user_input)   # 返回规范化绝对路径或 None
    if abs_path and is_path_under(abs_path, base_dir):
        ...  # 安全，可以读取
"""
import os


def safe_join(base, *parts):
    """
    安全拼接路径，防止目录穿越。

    1. 对 base 做 os.path.realpath 解析 symlink
    2. 拼接用户输入的 parts
    3. 对结果做 os.path.realpath 解析 symlink + normalize
    4. 检查结果是否在 base 下

    Args:
        base: 允许的根目录（绝对路径）
        *parts: 用户输入的路径片段

    Returns:
        str: 规范化后的绝对路径（在 base 下）
        None: 如果路径逃逸了 base 或路径不存在
    """
    if not base:
        return None

    real_base = os.path.realpath(base)

    # 拼接用户输入
    if not parts:
        return real_base

    # 过滤空片段
    parts = [p for p in parts if p is not None and p != '']
    if not parts:
        return real_base

    joined = os.path.join(real_base, *parts)
    real_joined = os.path.realpath(joined)

    # 检查是否在 base 下（兼容 / 和 os.sep）
    if not _is_under(real_joined, real_base):
        return None

    return real_joined


def is_path_under(path, base):
    """
    检查 path 是否在 base 目录下（含 base 自身）。

    使用 os.path.realpath 解析 symlink，防止通过符号链接绕过。

    Args:
        path: 待检查的路径
        base: 允许的根目录

    Returns:
        bool: True 如果 path 在 base 下
    """
    if not path or not base:
        return False
    real_path = os.path.realpath(path)
    real_base = os.path.realpath(base)
    return _is_under(real_path, real_base)


def _is_under(path, base):
    """
    内部方法：检查 path 是否以 base + os.sep 开头或等于 base。
    """
    if path == base:
        return True
    # 兼容不同分隔符（Windows 上 base 可能是 C:\\foo，path 可能是 C:/foo/bar）
    return (path.startswith(base + os.sep) or
            path.startswith(base + '/'))


# ── 快捷校验函数 ──

def require_under(base, user_input):
    """
    校验用户输入路径是否安全（在 base 下），返回安全的绝对路径。
    用于 API 视图中快速校验。

    Args:
        base: 允许的根目录
        user_input: 用户输入的相对路径

    Returns:
        tuple: (safe_path, error_response)
            safe_path: 安全的绝对路径，如果校验失败则为 None
            error_response: None 如果成功，或 (status_code, message) 如果失败
    """
    if not user_input or not isinstance(user_input, str):
        return None, (404, "no path specified")

    safe = safe_join(base, user_input)
    if safe is None:
        return None, (403, "path traversal forbidden")

    return safe, None
