from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),  # 登录页面
    path('register/', views.register_view, name='register'),
    path('afterLogin/', views.afterLogin_view, name='afterLogin'),
]