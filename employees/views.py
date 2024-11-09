from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.db import connection
from django.http import HttpResponse
from django.shortcuts import render
from .models import Feedback
from django.views.decorators.csrf import csrf_exempt
import pickle
from django.http import HttpResponse

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'employees/login.html', {'form': form})

def dashboard(request):
    return render(request, 'employees/dashboard.html')

def search_employee(request):
    name = request.GET.get('name', '')
    results = []
    if name:
        # Vulnerable SQL query directly using user input without parameterization
        query = f"SELECT * FROM employees_employee WHERE name = '{name}'"
        with connection.cursor() as cursor:
            cursor.execute(query)
            results = cursor.fetchall()

    return render(request, 'employees/search.html', {'results': results})

def admin_view(request):
    # No access control check to restrict this view to admin users only
    return render(request, 'employees/admin.html')

def set_user_role(request):
    if request.method == 'POST':
        # Insecurely serialize user role in the session
        role = request.POST.get('role', 'user')
        request.session['user_role'] = pickle.dumps(role)
        return HttpResponse("Role set successfully!")
    return render(request, 'employees/set_role.html')

def get_user_role(request):
    # Insecurely deserialize user role without validation
    role = pickle.loads(request.session.get('user_role', pickle.dumps('guest')))
    return render(request, 'employees/get_role.html', {'role': role})

@csrf_exempt
def feedback_view(request):
    if request.method == 'POST':
        content = request.POST.get('content', '')
        Feedback.objects.create(content=content)
    feedback_list = Feedback.objects.all()
    return render(request, 'employees/feedback.html', {'feedback_list': feedback_list})

def logout_view(request):
    logout(request)
    return redirect('login')
