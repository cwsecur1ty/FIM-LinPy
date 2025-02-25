# auth.py

from flask import Blueprint, render_template_string, request, session, redirect

auth_bp = Blueprint('auth', __name__)

login_template = """
<!doctype html>
<html>
<head>
    <title>Login - FIM-LinPy</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; }
        .container { max-width: 400px; margin: 0 auto; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 15px; background: #007BFF; color: white; border: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Login</button>
        </form>
        {% if error %}
            <p style="color: red;">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # In production, use secure password storage & validation.
        if username == "admin" and password == "password123":
            session["logged_in"] = True
            return redirect("/")
        else:
            error = "Invalid username or password"
            return render_template_string(login_template, error=error)
    return render_template_string(login_template)

@auth_bp.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect("/login")
