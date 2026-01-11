from flask import Flask, render_template, request, redirect, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from groq import Groq
import json
import os

from models import db, User, Idea

# ---------------- APP CONFIG ----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "ideascopesecret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# ---------------- GROQ SETUP ----------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Do NOT crash in production if missing (Render injects it later)
client = None
if GROQ_API_KEY:
    client = Groq(api_key=GROQ_API_KEY)

# ---------------- LOGIN ----------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ---------------- SAFETY FILTER ----------------
def is_unsafe(text):
    unsafe_words = ["fight","weapon","kill","attack","gang","riot","bomb","shoot","stab","violence","war","terror","gun"]
    return any(w in text.lower() for w in unsafe_words)

# ---------------- ROUTES ----------------
@app.route("/")
def landing():
    return render_template("landing.html")

# -------- Register --------
@app.route("/register", methods=["GET","POST"])
def register():
    error = None
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm = request.form["confirm"]

        if not email or not password:
            error = "All fields are required."
        elif password != confirm:
            error = "Passwords do not match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif User.query.filter_by(email=email).first():
            error = "An account with this email already exists."
        else:
            hashed = generate_password_hash(password)
            user = User(email=email, password=hashed)
            db.session.add(user)
            db.session.commit()
            return redirect("/login")

    return render_template("register.html", error=error)

# -------- Login --------
@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if not user:
            error = "No account found with this email."
        elif not check_password_hash(user.password, password):
            error = "Incorrect password."
        else:
            login_user(user)
            return redirect("/dashboard")

    return render_template("login.html", error=error)

# -------- Logout --------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

# -------- AI Question Generator --------
@app.route("/questions", methods=["POST"])
@login_required
def questions():
    if not client:
        return jsonify({"error": "AI service not configured"}), 500

    data = request.json
    idea = data.get("idea","").strip()

    if not idea:
        return jsonify({"error":"Idea cannot be empty"}),400

    if is_unsafe(idea):
        return jsonify({"unsafe":True,"message":"Unsafe idea detected"})

    prompt = f"""
    Ask 3 strong validation questions for this startup idea.
    Return JSON only.

    Idea: {idea}

    Format:
    {{ "questions": ["Q1","Q2","Q3"] }}
    """

    try:
        res = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role":"user","content":prompt}],
            response_format={"type":"json_object"}
        )
        return jsonify(json.loads(res.choices[0].message.content))
    except:
        return jsonify({"questions":[
            "Who is the customer?",
            "How will you get users?",
            "How will you make money?"
        ]})

# -------- AI Idea Analyzer --------
@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    if not client:
        return jsonify({"error": "AI service not configured"}), 500

    data = request.json
    idea = data.get("idea","")
    answers = data.get("answers",[])

    context = "\n".join([f"A{i+1}: {a}" for i,a in enumerate(answers)])

    prompt = f"""
    Analyze this startup idea deeply and return JSON.

    Idea: {idea}
    {context}

    JSON:
    {{
      "score": 0-10,
      "market": "",
      "users": "",
      "problem": "",
      "risk": "",
      "suggestion": "",
      "detailed_analysis": ""
    }}
    """

    try:
        res = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role":"user","content":prompt}],
            response_format={"type":"json_object"}
        )
        data = json.loads(res.choices[0].message.content)
    except:
        return jsonify({"error":"AI failed"}),500

    idea_obj = Idea(
        title=idea[:50],
        content=idea,
        analysis=json.dumps(data),
        score=int(data.get("score",5)),
        user_id=current_user.id
    )
    db.session.add(idea_obj)
    db.session.commit()

    return jsonify(data)

# -------- Dashboard --------
ADMIN_EMAILS = ["admin@ideascope.com"]

@app.route("/dashboard")
@login_required
def dashboard():
    history = Idea.query.filter_by(user_id=current_user.id).order_by(Idea.id.desc()).all()
    return render_template("index.html", history=history)

@app.route("/admin")
@login_required
def admin():
    if current_user.email not in ADMIN_EMAILS:
        return "Forbidden",403
    return "Admin Panel"

# ---------------- RUN ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
