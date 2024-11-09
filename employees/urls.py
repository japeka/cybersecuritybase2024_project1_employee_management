from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'), 
    path('logout/', views.logout_view, name='logout'),
    path('search/', views.search_employee, name='search_employee'),    
    path('admin/', views.admin_view, name='admin_view'),
    path('feedback/', views.feedback_view, name='feedback_view'),
    path('role/set/', views.set_user_role, name='set_user_role'),
    path('role/get/', views.get_user_role, name='get_user_role'),
]