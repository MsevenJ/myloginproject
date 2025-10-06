# accounts/forms.py
from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from captcha.fields import CaptchaField
import re
from django.core.exceptions import ValidationError

class CaptchaLoginForm(AuthenticationForm):
    captcha = CaptchaField(label='验证码')


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, label='邮箱')
    captcha = CaptchaField(label='验证码')

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', 'captcha')

    # 密码强度规则
    def clean_password1(self):
        password = self.cleaned_data.get('password1')

        if not password:
            raise ValidationError('密码不能为空')


        errors = []

        if not re.search(r'[A-Z]', password):
            errors.append('密码必须包含至少一个大写字母 (A-Z)')
        if not re.search(r'[a-z]', password):
            errors.append('密码必须包含至少一个小写字母 (a-z)')
        if not re.search(r'[0-9]', password):
            errors.append('密码必须包含至少一个数字 (0-9)')
        if not re.search(r'[ !@#$%^&*()\-_=+{}\[\]|\\;:\'",.<>/?`~]', password):
            errors.append('密码必须包含至少一个特殊字符 (如 !@#$%^&* 等)')
        if len(password) <= 8:
            raise ValidationError('密码长度必须大于 8 个字符')

        if errors:
            raise ValidationError('密码强度不足：' + ''.join(errors))

        return password

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError('用户名已存在')
        if len(username) < 3:
            raise ValidationError('用户名长度必须大于 3 个字符')
        if len(username) > 20:
            raise ValidationError('用户名长度不能大于 20 个字符')
        return username


    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user








class StrongPasswordLoginForm(AuthenticationForm):
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')

        if not password:
            raise forms.ValidationError('密码不能为空')

        has_upper = re.search(r'[A-Z]', password)
        has_lower = re.search(r'[a-z]', password)
        has_digit = re.search(r'[0-9]', password)
        has_special = re.search(r'[!@#$%^&*()\_-=+{}\[\]|\\;:\'",.<>/?`~]', password)

        errors = []

        if not has_upper:
            errors.append('密码必须包含大写字母')
        if not has_lower:
            errors.append('密码必须包含小写字母')
        if not has_digit:
            errors.append('密码必须包含数字')
        if not has_special:
            errors.append('密码必须包含特殊字符')

        if errors:
            raise ValidationError("密码强度不足：<br/>" + "<br/>".join(errors))

        return cleaned_data