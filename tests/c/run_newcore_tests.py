#!/usr/bin/env python3
"""C NewCore benchmark test runner.

Tests that C NewFunction (code=5) correctly triggers NewCore second-pass
scanning for cross-file wrapped sink functions.

Usage:
    cd /path/to/Kunlun-M
    source /path/to/venv/bin/activate
    python tests/c/run_newcore_tests.py
"""
import json
import os
import subprocess
import sys
import time

_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
test_dir = os.path.join(_repo_root, 'tests', 'c')
ci_scan = os.path.join(_repo_root, 'tools', 'ci_scan.py')
output_dir = os.path.join(test_dir, '_newcore_output')

# (main_file, language, should_detect, description, expected_cvis)
# C NewCore: cross-file wrapper functions
test_cases = [
    # 25: 单层跨文件封装 - 命令注入
    ('25b_newfunc_exec_main.c', 'c', True, '跨文件 executeCommand(argv[1]) -> system',
     ['CVI-9001']),
    # 26: 单层跨文件封装 - 格式化字符串
    ('26b_newfunc_sqli_main.c', 'c', True, '跨文件 logMessage(getenv) -> sprintf',
     ['CVI-9002']),
    # 27: 单层跨文件封装 - 路径穿越
    ('27b_newfunc_path_main.c', 'c', True, '跨文件 readConfig(argv[1]) -> fopen',
     ['CVI-9004']),
    # 28: 跨文件返回值
    ('28b_newfunc_return_main.c', 'c', True, '跨文件 readInput() -> strcpy+system',
     ['CVI-9001', 'CVI-9003']),
    # 29: 多 sink 封装
    ('29b_newfunc_multi_main.c', 'c', True, '跨文件 multi wrapper: runCommand+loadFile+formatOutput',
     ['CVI-9001', 'CVI-9002', 'CVI-9004']),
]


def run_scan():
    """Run ci_scan on the entire C test directory and return JSON results."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'scan_results.json')

    cmd = [
        sys.executable, ci_scan,
        '--language', 'c',
        '--target', test_dir,
        '--output', out_path,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=_repo_root)
        if result.returncode != 0:
            print(f"  [STDERR] {result.stderr.strip()[:300]}")
            return None
        if os.path.exists(out_path):
            with open(out_path) as f:
                return json.load(f)
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] scan exceeded 120s")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return None


def extract_vulns_for_file(results, target_file):
    """Extract list of CVI IDs from scan results for a specific file."""
    if not results:
        return []
    vulns = []

    items = []
    if isinstance(results, list):
        items = results
    elif isinstance(results, dict):
        for key in ('results', 'vulnerabilities', 'data'):
            if key in results and isinstance(results[key], list):
                items = results[key]
                break

    for item in items:
        if not isinstance(item, dict):
            continue
        file_val = item.get('file') or item.get('file_path') or item.get('file_name') or ''
        # Match if target_file is in the file path
        if target_file in file_val:
            cvi = item.get('cvi_id') or item.get('cvi') or item.get('vuln_class') or ''
            cvi_str = str(cvi)
            # cvi_id might be "9001" without CVI prefix, normalize it
            if cvi_str.isdigit():
                cvi_str = 'CVI-' + cvi_str
            if 'CVI' in cvi_str:
                vulns.append(cvi_str)

    return vulns


def main():
    print("=" * 70)
    print("C NewCore Benchmark Test")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)

    # Run scan once for all test cases
    print("\nRunning ci_scan on tests/c/ ...")
    t0 = time.time()
    results = run_scan()
    elapsed = time.time() - t0
    print(f"Scan completed in {elapsed:.1f}s")

    if results is None:
        print("ERROR: scan failed, aborting")
        return 1

    # Debug: show all detected vulnerabilities
    items = []
    if isinstance(results, list):
        items = results
    elif isinstance(results, dict):
        for key in ('results', 'vulnerabilities', 'data'):
            if key in results and isinstance(results[key], list):
                items = results[key]
                break

    print(f"\nTotal vulnerabilities detected: {len(items)}")
    for item in items:
        if isinstance(item, dict):
            f = item.get('file', '')
            c = item.get('cvi_id', '')
            print(f"  {f} {c}")

    passed = 0
    failed = 0
    errors = 0

    for test_file, lang, should_detect, desc, expected_cvis in test_cases:
        print(f"\n[{test_file}] {desc}")
        print(f"  Expected: detect={should_detect}, CVIs={expected_cvis}")

        vulns = extract_vulns_for_file(results, test_file)
        detected = len(vulns) > 0

        if should_detect:
            found_cvis = set(vulns)
            missing = set(expected_cvis) - found_cvis
            if not missing:
                print(f"  Result: PASS (detected {vulns})")
                passed += 1
            else:
                print(f"  Result: FAIL (detected {vulns}, missing {missing})")
                failed += 1
        else:
            if detected:
                print(f"  Result: FAIL (false positive: {vulns})")
                failed += 1
            else:
                print(f"  Result: PASS (correctly not detected)")
                passed += 1

    print(f"\n{'=' * 70}")
    print(f"Results: {passed} passed, {failed} failed, {errors} errors out of {len(test_cases)}")
    print(f"{'=' * 70}")

    return 0 if (failed == 0 and errors == 0) else 1


if __name__ == '__main__':
    sys.exit(main())
