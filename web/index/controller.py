#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: controller.py
@time: 2021/6/16 18:07
@desc:

'''


from functools import wraps

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, JsonResponse

import django.utils.timezone as timezone

from web.index.models import ScanTask

from Kunlun_M.settings import API_TOKEN


def login_or_token_required(function):

    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated:
            return function(request, *args, **kwargs)
        else:
            if "token" in request.GET:
                task_id = kwargs['task_id'] if 'task_id' in kwargs else 0

                task = ScanTask.objects.filter(id=task_id).first()

                if request.GET['token'] == task.visit_token:
                    return function(request, *args, **kwargs)
             
            next = request.get_full_path()
            red = HttpResponseRedirect('/login/?next=' + next)
            return red

    return wrapper


def api_token_required(function):
    """API Token 鉴权：先查 ApiToken 模型，fallback 到全局 API_TOKEN"""
    @wraps(function)
    def wrapper(request, *args, **kwargs):
        token_value = request.GET.get('apitoken') or request.POST.get('apitoken') or ''
        token_value = token_value.strip()

        if token_value:
            # 优先查 ApiToken 模型
            from .models import ApiToken
            try:
                at = ApiToken.objects.filter(token=token_value, is_active=True).select_related('user').first()
                if at:
                    at.last_used_at = timezone.now()
                    at.save(update_fields=['last_used_at'])
                    request._api_token_user = at.user
                    return function(request, *args, **kwargs)
            except Exception:
                pass

            # fallback 到全局 API_TOKEN
            if token_value == API_TOKEN:
                return function(request, *args, **kwargs)

        return JsonResponse({"code": 401, "status": "error", "message": "Auth check error. token required."})
    return wrapper


def admin_required(function):
    """要求用户是管理员（is_staff=True）"""
    @wraps(function)
    def wrapper(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_staff:
            return function(request, *args, **kwargs)
        return HttpResponseRedirect('/')
    return wrapper
