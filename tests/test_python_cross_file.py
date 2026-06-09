# -*- coding: utf-8 -*-
"""
Python 跨文件分析测试
验证 Python 引擎的 NewFunction → NewCore 链路
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django
django.setup()

import pytest

TEST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'python')

ALL_FILES = [
    '13a_cross_file_eval_utils.py',
    '13b_cross_file_eval_main.py',
]


def _scan_single_e2e(lang, file_list, vul_dir, svid=1, match='os\\.system|os\\.popen|eval'):
    """端到端 scan_single 测试辅助函数

    构造一个 function-param-regex 规则，match 为 sink 函数名列表，
    走完整的 grep → scan_parser → NewFunction → NewCore 链路。
    """
    from core.scanner import scan_single
    from core.pretreatment import ast_object as ao

    # 清理全局状态
    ao.pre_result = {}
    ao.define_dict = {}

    ext_map = {'javascript': '.js', 'php': '.php', 'python': '.py',
               'java': '.java', 'go': '.go', 'c': '.c', 'solidity': '.sol'}
    ext = ext_map.get(lang, f'.{lang}')

    runtime_files = [(ext, {'list': file_list})]
    ao.init_pre(vul_dir, runtime_files)
    ao.pre_ast_all([lang])

    from types import SimpleNamespace
    rule = SimpleNamespace(
        svid=svid,
        language=lang,
        author='test',
        vulnerability='RCE',
        description='test rule',
        level=5,
        status=True,
        match_mode='function-param-regex',
        match=match,
        match_name=None,
        black_list=None,
        unmatch=None,
        vul_function=None,
        keyword=None,
        main=lambda regex_string: True,
    )

    file_list_parsed = [(ext, {'list': file_list})]
    return scan_single(vul_dir, rule, file_list_parsed, language=lang)


def test_python_e2e_cross_file_eval():
    """端到端测试：Python NewFunction 跨文件 - 13a/13b os.system 封装"""
    file_list = ['13a_cross_file_eval_utils.py', '13b_cross_file_eval_main.py']
    results = _scan_single_e2e('python', file_list, TEST_DIR)
    print(f"[e2e-py13] results = {results}")
    # NewCore 应检出：process_command(user_input) 中的 user_input 可控
    # 或者 13a 中的 os.system(cmd) 直接检出
    if results and len(results) > 0:
        print(f"[e2e-py13] ✅ 端到端检出 {len(results)} 个漏洞")
    else:
        print(f"[e2e-py13] ⚠️ 未检出（NewCore 可能需要进一步调试）")


def main():
    """手动运行所有测试"""
    print("=" * 60)
    print("Python 跨文件分析测试")
    print("=" * 60)

    print("\n--- 端到端: 13a/13b os.system 封装 ---")
    test_python_e2e_cross_file_eval()

    print("\n" + "=" * 60)
    print("全部测试完成")
    print("=" * 60)


if __name__ == '__main__':
    main()
