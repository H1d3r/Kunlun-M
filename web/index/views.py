#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/1/29 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com


from django.shortcuts import render, redirect
from django.contrib import auth
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm

from Kunlun_M.settings import TITLE, DESCRIPTION, IS_OPEN_REGISTER

base = {
        "title": TITLE,
        "description": DESCRIPTION,
        "is_open_register": IS_OPEN_REGISTER
    }


def index(req):
    auth_modal = req.GET.get('auth', '')
    context = dict(base)
    context['auth_modal'] = auth_modal
    return render(req, 'index.html', context)


def signup(req):

    if not IS_OPEN_REGISTER:
        return redirect('index:index')

    if req.method == 'POST':
        form = UserCreationForm(req.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')

            # SUPER_ADMIN 中的用户自动设为管理员
            from Kunlun_M.settings import SUPER_ADMIN
            new_user = form.save(commit=False)
            if username in SUPER_ADMIN:
                new_user.is_staff = True
            new_user.save()

            password = form.cleaned_data.get('password1')
            user = auth.authenticate(username=username, password=password)

            if user is not None and user.is_active:
                auth.login(req, user)
                return redirect('index:index')
            else:
                return redirect('/?auth=register')
        else:
            messages.add_message(req, messages.ERROR, form.errors)
            return redirect('/?auth=register')
    else:
        return redirect('/?auth=register')


def signin(req):
    if req.method == 'POST':
        username = req.POST['username']
        password = req.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None and user.is_active:
            auth.login(req, user)
            return redirect('index:index')
        else:
            messages.add_message(req, messages.ERROR, "Username or Password is incorrect.")
            return redirect('/?auth=login')
    else:
        return redirect('/?auth=login')


def logout(req):
    auth.logout(req)
    return redirect('index:index')
