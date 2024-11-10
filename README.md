# Security Analysis Report: Employee Management Application

In this assignment, I implemented a Django-based employee management application with intentionally insecure code that demonstrates five key security vulnerabilities from the **2017 OWASP Top 10 List**. This application and its codebase illustrate common security flaws and provide opportunities to understand how to fix each issue. Below is a description of each flaw, its implementation, and proposed fixes.

## Repository and Installation Instructions

### Repository Link
[GitHub Repository for the Employee Management Application](https://github.com/japeka/cybersecuritybase2024_project1_employee_management)

### Installation Steps

1. **Clone the Repository**:
```bash
git clone https://github.com/japeka/cybersecuritybase2024_project1_employee_management.git
cd cybersecuritybase2024_project1_employee_management
```

2. **Install Dependencies**:
Install the necessary packages using `requirements.txt`.
```bash
pip install -r requirements.txt
```

3. **Apply Database Migrations**:
Run migrations to set up the database.
```bash
python manage.py makemigrations
python manage.py migrate
```

4. **Create a Superuser Account**:
```bash
python manage.py createsuperuser
```

5. **Start the Django Development Server**:
```bash
python manage.py runserver
```

6. **Access the Application**:
Open `http://127.0.0.1:8000/` in a browser. This will redirect to the login page.

---

## Security Flaws in This Application

### FLAW 1: A01:2017-Injection

- **Source**: [views.py, Line 31](https://github.com/japeka/cybersecuritybase2024_project1_employee_management/blob/main/employees/views.py#L31)

- **Description**: This flaw demonstrates SQL injection by using unsanitized user input directly in an SQL query. By concatenating the user-provided input without parameterization, attackers can execute arbitrary SQL commands, potentially exposing or modifying sensitive data.
**Example**: When a user accesses `/employees/search/?name=' OR '1'='1`, this input could manipulate the SQL query to return all records.

- **Fix**: Use parameterized queries to securely pass user input as data, not executable code.
```python
query = "SELECT * FROM employees_employee WHERE name = %s"
with connection.cursor() as cursor:
cursor.execute(query, [name]) # Secure parameterized query
results = cursor.fetchall()
```

---

### FLAW 2: A05:2017-Broken Access Control
- **Source**: [views.py, Line 40](https://github.com/japeka/cybersecuritybase2024_project1_employee_management/blob/main/employees/views.py#L40)

- **Description**: This flaw illustrates broken access control by allowing any logged-in user to access the `admin_view` page, which should be restricted to admin users only. Without proper access checks, non-admin users can access sensitive functionality, potentially leading to privilege escalation.

- **Fix**: Use Django’s `@staff_member_required` decorator to restrict access to staff members (i.e., admin users) only.
```python
from django.contrib.admin.views.decorators import staff_member_required
@staff_member_required
def admin_view(request):
return render(request, 'employees/admin.html')
```

---

### FLAW 3: A07:2017-Cross-Site Scripting (XSS)
- **Source**: [views.py, Line 58-59](https://github.com/japeka/cybersecuritybase2024_project1_employee_management/blob/main/employees/views.py#L58-L59)

- **Description**: This XSS flaw occurs because user-submitted feedback is displayed without sanitization, allowing attackers to inject malicious JavaScript. For example, input like `<script>alert('XSS')</script>` can execute unwanted JavaScript in the user’s browser, leading to potential session hijacking or unauthorized actions.

- **Fix**: Use the `bleach` library to sanitize input and remove disallowed HTML tags. Alternatively, use Django’s `strip_tags` to remove HTML tags entirely for plain text input.
```python
import bleach
@csrf_exempt
def feedback_view(request):
if request.method == 'POST':
content = request.POST.get('content', '')
safe_content = bleach.clean(content, tags=['b', 'i', 'u', 'p'], attributes={}, styles=[], strip=True)
Feedback.objects.create(content=safe_content)
feedback_list = Feedback.objects.all()
return render(request, 'employees/feedback.html', {'feedback_list': feedback_list})
```
---

### FLAW 4: A02:2017-Broken Authentication

- **Source**: [views.py, Line 12-21](https://github.com/japeka/cybersecuritybase2024_project1_employee_management/blob/main/employees/views.py#L12-L21)

- **Description**: This flaw shows broken authentication due to a lack of secure session management and multi-factor authentication. By default, sessions remain active for extended periods, allowing potential attackers to exploit session-based vulnerabilities.

- **Fix**: Set session timeouts for added security and consider implementing multi-factor authentication (MFA). Use the `SESSION_COOKIE_AGE` setting to limit session duration.
```python
# settings.py
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 600 # Session expires after 10 minutes
# In views.py
def login_view(request):
if request.method == 'POST':
form = AuthenticationForm(request, data=request.POST)
if form.is_valid():
user = form.get_user()
login(request, user)
request.session.set_expiry(600) # Session expires after 10 minutes
return redirect('dashboard')
else:
form = AuthenticationForm()
return render(request, 'employees/login.html', {'form': form})
```

---

### FLAW 5: A08:2017-Insecure Deserialization
- **Source**: [views.py, Lines 46 and 52](https://github.com/japeka/cybersecuritybase2024_project1_employee_management/blob/main/employees/views.py#L46 and #L52)

- **Description**: Insecure deserialization occurs when user role data is serialized using `pickle`, which can execute arbitrary code during deserialization. This allows attackers to modify session data and gain unauthorized privileges.

- **Fix**: Replace `pickle` with `json`, which safely serializes data without code execution. Additionally, validate deserialized data to ensure it only contains allowed values.
```python
import json
def set_user_role(request):
if request.method == 'POST':
role = request.POST.get('role', 'user')
request.session['user_role'] = json.dumps(role)
return HttpResponse("Role set successfully!")
return render(request, 'employees/set_role.html')

def get_user_role(request):
role = json.loads(request.session.get('user_role', json.dumps('guest')))
if role not in ['user', 'admin']:
role = 'guest'
return render(request, 'employees/get_role.html', {'role': role})
```

# Conclusion

The employee management application developed in this project effectively highlights five critical vulnerabilities from the **OWASP Top 10 2017 List**. By implementing and addressing these flaws, we gain a deeper understanding of both the technical mechanisms behind common security issues and the best practices for mitigating them. Secure coding practices, as demonstrated in the proposed fixes, are essential for building applications that protect user data, maintain integrity, and ensure availability in the face of potential attacks.

Injection flaws, broken access control, XSS vulnerabilities, authentication weaknesses, and insecure deserialization each pose unique risks. However, they all underscore the importance of treating user input with caution, enforcing strict access controls, validating data rigorously, and adhering to the principle of least privilege. As web applications often handle sensitive information, any mishandling or weak enforcement in these areas could lead to severe consequences, including data breaches, unauthorized access, and compromised user accounts.

One key takeaway from this exercise is the necessity of **defense-in-depth**: implementing multiple layers of security that collectively reduce the likelihood and impact of attacks. For instance, while setting session timeouts and sanitizing user input are important, they’re even more effective when combined with parameterized queries and secure serialization methods. Defense-in-depth ensures that even if one security control fails, others remain to help prevent exploitation.

Moreover, maintaining security in applications is an ongoing process. As demonstrated in this project, using libraries like `bleach` for sanitizing user input and replacing unsafe serialization methods with safer alternatives like JSON helps us mitigate risks, but these solutions must be kept up-to-date with the latest security standards. Regularly reviewing and updating application dependencies, monitoring for new vulnerabilities, and integrating automated security tools such as Static Application Security Testing (SAST) tools can help developers stay ahead of evolving threats.

Lastly, it’s essential to foster a security-conscious development culture. Regular training on secure coding practices, coupled with a thorough understanding of vulnerabilities and mitigation techniques, empowers developers to make proactive decisions that prevent security issues from arising in the first place. By prioritizing security at each stage of development, from design to deployment, organizations can not only protect their applications from exploitation but also build user trust and demonstrate a commitment to safeguarding their data.

In summary, this project serves as a practical guide to identifying and addressing some of the most common security flaws in web applications. It emphasizes that security is not an afterthought but an integral part of development that requires diligence, awareness, and continuous improvement. Adopting these principles will strengthen the overall security of any Django-based application and enhance resilience against potential cyber threats.