from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from accounts.forms import CaptchaLoginForm, RegisterForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import AnonymousUser


# 登录
def login_view(request):
    if request.method == 'POST':
        form = CaptchaLoginForm(request, data=request.POST)
        if form.is_valid():
            username = request.POST.get('username')
            password = request.POST.get('password')

            # 验证用户名密码
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, '登陆成功')
                return redirect('/accounts/afterLogin')
            else:
                messages.error(request, '用户名密码错误')
                # return render(request, 'account/login.html', {'error': 'Invalid username or password'})
        else:
            messages.error(request, '请检查您的输入内容')
    else:
        form = CaptchaLoginForm(request)

    #print("form fields:",form.fields.keys())
    return render(request, 'account/login.html', {'form': form})


# 注册
def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'账号 {username} 创建成功，请登录')
            return redirect('login')  # 注册成功后跳转到登录页
        else:
            # 显示表单验证错误
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = RegisterForm()

    return render(request, 'account/register.html', {'form': form})


@login_required
def afterLogin_view(request):
    return render(request, 'account/afterLogin.html')

