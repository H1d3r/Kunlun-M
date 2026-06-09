# -*- coding: utf-8 -*-
"""
Python 跨文件 benchmark: main 模块
import utils 后调用其中包含危险函数的方法
"""
import sys
import os

# 模拟跨文件 import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import process_command, evaluate_expression


# sys.argv[2] 是可控 source
user_input = sys.argv[2]

# 调用跨文件函数，参数来自可控 source
process_command(user_input)
