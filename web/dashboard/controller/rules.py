#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/5 10:41
# @Author  : LoRexxar
# @File    : rules.py
# @Contact : lorexxar@gmail.com
import os

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseNotFound
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render

from web.index.models import Rules
from Kunlun_M.settings import RULES_PATH


def _read_rule_source(rule):
    """从源文件读取规则源码，读不到返回 None"""
    if not rule.language or not rule.svid:
        return None
    rule_file = os.path.join(RULES_PATH, rule.language, 'CVI_{}.py'.format(rule.svid))
    if not os.path.isfile(rule_file):
        return None
    try:
        with open(rule_file, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception:
        return None


class RuleListView(TemplateView):
    """展示所有规则，按语言分组"""
    template_name = "dashboard/rules/rules_list.html"

    def get_context_data(self, **kwargs):
        context = super(RuleListView, self).get_context_data(**kwargs)

        rows = Rules.objects.values('id', 'svid', 'rule_name', 'language', 'level', 'status', 'match_mode').order_by('svid')

        # 按语言分组
        lang_order = ['php', 'python', 'javascript', 'java', 'go', 'c', 'solidity', 'chromeext']
        lang_groups = {}
        for r in rows:
            lang = (r['language'] or 'unknown').lower()
            lang_groups.setdefault(lang, []).append(r)

        sorted_groups = []
        for lang in lang_order:
            if lang in lang_groups:
                sorted_groups.append((lang, lang_groups.pop(lang)))
        for lang in sorted(lang_groups.keys()):
            sorted_groups.append((lang, lang_groups[lang]))

        context['lang_groups'] = sorted_groups
        return context


class RuleSourceJsonView(View):
    """返回单条规则的源码，供前端 AJAX 加载"""
    @staticmethod
    @login_required
    def get(request, rule_id):
        row = Rules.objects.filter(id=rule_id).first()
        if not row:
            return JsonResponse({'error': 'Rule Not Found'}, status=404)

        source = _read_rule_source(row)
        return JsonResponse({
            'source': source or '',
            'rule_name': row.rule_name,
            'language': row.language,
            'svid': row.svid,
            'level': row.level,
            'status': row.status,
            'description': row.description,
            'author': row.author,
            'match_mode': row.match_mode,
        })


class RuleDetailView(View):
    """展示规则细节（保留旧链接兼容）"""

    @staticmethod
    @login_required
    def get(request, rule_id):
        row = Rules.objects.filter(id=rule_id).first()

        if not row:
            return HttpResponseNotFound('Rule Not Found.')

        source_code = _read_rule_source(row)

        data = {
            'rule': row,
            'source_code': source_code,
        }
        return render(request, 'dashboard/rules/rules_detail.html', data)
