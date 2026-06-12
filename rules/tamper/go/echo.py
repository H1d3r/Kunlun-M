# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'Echo'
DEPENDENCIES = {'gomod': ['github.com/labstack/echo']}


def detect(project_dir, language='go'):
    """检测是否为 Echo 项目"""
    return False


FILTER_FUNCTIONS = {}

CONTROLLED_SOURCES = [
    'c.QueryParam',
    'c.Param',
    'c.FormValue',
    'c.Request.FormValue',
    'c.QueryString',
]

EXTRA_SINKS = []
