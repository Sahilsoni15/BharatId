from flask import Flask, render_template, request, session, redirect, url_for, flash
from datetime import datetime, timedelta
import re, random, os, io, uuid, logging
from PIL import Image
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import firebase_admin
from firebase_admin import credentials, db, storage

# ---------------- App Setup ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")
app.permanent_session_lifetime = timedelta(days=30)

EMAIL_SUFFIX = "@bharatmail.id"
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}
AVATAR_COLORS = ["1abc9c","3498db","9b59b6","e74c3c","f39c12","2ecc71"]

logging.basicConfig(level=logging.DEBUG)

# ---------------- Firebase Init ----------------
# ---------------- Firebase Init ----------------
import json

firebase_key = os.getenv("FIREBASE_KEY")

if firebase_key:
    # Railway pe JSON env se
    cred = credentials.Certificate(json.loads(firebase_key))
else:
    # Local development ke liye file se
    cred = credentials.Certificate("serviceAccountKey.json")

firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://bharat-id-default-rtdb.firebaseio.com',
    'storageBucket': 'bharat-id.appspot.com'
})

# ----------------- Utils -----------------
def _validate_password(password: str) -> str | None:
    if len(password) < 6:
        return "Password must be at least 6 characters."
    if not re.search(r"[A-Za-z]", password):
        return "Password must include at least one letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    return None

def is_valid_username(username: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9]+", username) is not None

def suggest_email(username: str) -> str:
    return f"{username}{random.randint(10, 99)}{EMAIL_SUFFIX}"

def email_to_key(email: str) -> str:
    return email.replace(".", ",").replace("#", ",").replace("$", ",").replace("[", ",").replace("]", ",")

# ---------------- Firebase Storage Functions ----------------
def upload_avatar_to_firebase(img: Image.Image) -> str:
    try:
        img_bytes = io.BytesIO()
        img.save(img_bytes, format="JPEG", quality=90)
        img_bytes.seek(0)
        bucket = storage.bucket()
        blob_name = f"avatars/{uuid.uuid4().hex}.jpg"
        blob = bucket.blob(blob_name)
        blob.upload_from_file(img_bytes, content_type="image/jpeg")
        blob.make_public()
        logging.debug(f"Uploaded avatar to Firebase: {blob.public_url}")
        return blob.public_url
    except Exception:
        logging.exception("Failed uploading avatar")
        return None

def save_uploaded_avatar(file_storage) -> str:
    try:
        img = Image.open(file_storage.stream).convert("RGB")
        w, h = img.size
        side = min(w, h)
        img = img.crop(((w-side)//2, (h-side)//2, (w+side)//2, (h+side)//2)).resize((200, 200))
        return upload_avatar_to_firebase(img)
    except Exception:
        logging.exception("Failed processing uploaded avatar")
        return None

def generate_default_avatar(first_name: str, last_name: str) -> str:
    name_part = f"{first_name}+{last_name}".strip("+") or "?"
    bg = random.choice(AVATAR_COLORS)
    avatar_url = f"https://ui-avatars.com/api/?name={name_part}&background={bg}&color=000000&size=200"
    try:
        resp = requests.get(avatar_url)
        if resp.status_code == 200:
            img = Image.open(io.BytesIO(resp.content))
            firebase_url = upload_avatar_to_firebase(img)
            if firebase_url:
                return firebase_url
    except Exception:
        logging.exception("Failed generating default avatar")
    return avatar_url  # direct URL fallback

# ---------------- Routes ----------------
@app.route("/")
def home():
    return redirect(url_for("popup_login"))
    '''user_email = session.get("user_email")
    user_name = session.get("user_name", "")
    return f"""
    <h2>Main Site</h2>
    <div id="user-info">
        {'Logged in as: ' + user_name + ' (' + user_email + ')' if user_email else 'Not logged in'}
    </div>
    <button onclick="openBharatIDPopup()">Sign in with BharatID</button>
    <script>
    function openBharatIDPopup(){{
        const popup = window.open("/popup-login","BharatID Login","width=500,height=600,top=100,left=100");
        window.addEventListener("message", (event) => {{
            if(event.origin !== window.location.origin) return;
            const data = event.data;
            if(data.type === "login-success"){{
                document.getElementById("user-info").innerText =
                    "Logged in as: " + data.name + " (" + data.email + ")";
            }}
        }});
    }}
    </script>
    """'''

@app.route("/popup-login")
def popup_login():
    accounts = session.get("accounts", [])
    fixed_accounts = []

    for acc_email in accounts:
        key = email_to_key(acc_email)
        user_data = db.reference(f"users/{key}").get()
        if not user_data:
            continue
        avatar_url = user_data.get("profile_pic") or generate_default_avatar(user_data.get("first_name",""), user_data.get("last_name",""))
        fixed_accounts.append({
            "email": user_data["email"],
            "name": user_data.get("first_name") or user_data.get("username"),
            "avatar": avatar_url
        })

    session["accounts"] = [a["email"] for a in fixed_accounts]

    current_email = session.get("user_email")
    if current_email:
        fixed_accounts = sorted(
            fixed_accounts,
            key=lambda x: 0 if x["email"] == current_email else 1
        )

    return render_template("popup_login.html", accounts=fixed_accounts)

@app.route("/login", methods=["GET","POST"])
def login():
    add_mode = request.args.get("add")=="1"
    if request.method=="POST":
        email_or_username = request.form.get("email","").strip().lower()
        password = request.form.get("password","").strip()
        email = email_or_username if "@" in email_or_username else f"{email_or_username}{EMAIL_SUFFIX}"
        key = email_to_key(email)
        user = db.reference(f"users/{key}").get()
        if not user:
            flash("User not found!")
            return redirect(url_for("login"))
        if not check_password_hash(user.get("password_hash",""), password):
            flash("Incorrect password!")
            return redirect(url_for("login"))

        session_id = str(uuid.uuid4())
        session["session_id"] = session_id
        session_info = {
            "device_name": request.user_agent.platform or "Unknown",
            "browser": request.user_agent.browser or "Unknown",
            "os": request.user_agent.platform or "Unknown",
            "ip": request.remote_addr or "127.0.0.1",
            "last_active": datetime.now().isoformat(timespec="seconds"),
            "active": True,
            "user_agent_raw": request.user_agent.string
        }
        db.reference(f"users/{key}/sessions/{session_id}").set(session_info)

        accounts = session.get("accounts", [])
        if email in accounts: accounts.remove(email)
        accounts.insert(0, email)
        session["accounts"] = accounts
        session["user_email"] = email
        session["user_name"] = user.get("first_name","")
        session.permanent = True
        flash(f"Welcome {user.get('first_name','')}! You are logged in as {email}")
        return redirect(url_for("home"))

    return render_template("login.html", add_mode=add_mode)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---------------- Register Route ----------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        first_name = request.form.get("first_name","").strip()
        last_name = request.form.get("last_name","").strip()
        username = request.form.get("email","").strip().lower()
        password = request.form.get("password","").strip()

        if not username:
            flash("Username is required.")
            return redirect(url_for("register"))
        if not is_valid_username(username):
            flash("Email username can contain only letters and numbers.")
            return redirect(url_for("register"))
        pw_err = _validate_password(password)
        if pw_err:
            flash(pw_err)
            return redirect(url_for("register"))

        email = f"{username}{EMAIL_SUFFIX}"
        key = email_to_key(email)
        if db.reference(f"users/{key}").get():
            flash(f"Email already taken! Try: {suggest_email(username)}")
            return redirect(url_for("register"))

        # --- Avatar Handling ---
        avatar_url = None
        file = request.files.get("profile_pic")
        if file and file.filename:
            avatar_url = save_uploaded_avatar(file)
        if not avatar_url:
            avatar_url = generate_default_avatar(first_name, last_name)

        # --- Save user in Firebase ---
        db.reference(f"users/{key}").set({
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "phone": "",
            "profile_pic": avatar_url,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        })
        flash(f"Registration successful! Your email is {email}")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------- Update Profile Route ----------------
@app.route("/update_profile", methods=["POST"])
def update_profile():
    user_email = session.get("user_email")
    if not user_email:
        flash("No active session!")
        return redirect(url_for("login"))

    key = email_to_key(user_email)
    user_ref = db.reference(f"users/{key}")
    user = user_ref.get() or {}

    first_name = request.form.get("first_name","").strip()
    last_name = request.form.get("last_name","").strip()
    phone = request.form.get("phone","").strip()
    password = request.form.get("password","").strip()

    updates = {
        "first_name": first_name or user.get("first_name",""),
        "last_name": last_name or user.get("last_name",""),
        "phone": phone or user.get("phone","")
    }

    if password:
        pw_err = _validate_password(password)
        if pw_err:
            flash(pw_err)
            return redirect(url_for("home"))
        updates["password_hash"] = generate_password_hash(password)

    file = request.files.get("profile_pic")
    if file and file.filename:
        avatar_url = save_uploaded_avatar(file)
        if avatar_url:
            updates["profile_pic"] = avatar_url

    user_ref.update(updates)
    flash("Profile updated successfully!")
    return redirect(url_for("home"))
@app.route("/auth/callback")
def auth_callback():
    # Bharat ID popup login se email aur token milenge
    email = request.args.get("email")
    token = request.args.get("token")  # optional, if you use

    if not email:
        flash("Login failed! No email returned.")
        return redirect(url_for("popup_login"))

    # Firebase se user fetch karo
    key = email_to_key(email)
    user = db.reference(f"users/{key}").get()
    if not user:
        flash("User not found in DB.")
        return redirect(url_for("popup_login"))

    # Flask session create
    session_id = str(uuid.uuid4())
    session["session_id"] = session_id
    session["user_email"] = email
    session["user_name"] = user.get("first_name","")
    session.permanent = True

    # Firebase me session save
    session_info = {
        "device_name": request.user_agent.platform or "Unknown device",
        "browser": request.user_agent.browser or "Unknown browser",
        "os": request.user_agent.platform or "Unknown OS",
        "ip": request.remote_addr or "127.0.0.1",
        "last_active": datetime.now().isoformat(timespec="seconds"),
        "active": True,
    }
    db.reference(f"users/{key}/sessions/{session_id}").set(session_info)

    # Parent website ko data bhejne ke liye JS
    return f"""
    <script>
        window.opener.postMessage({{
            type: "login-success",
            email: "{email}",
            name: "{user.get('first_name','')}"
        }}, window.opener.location.origin);
        window.close();
    </script>
    """

# ---------------- Run App ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
