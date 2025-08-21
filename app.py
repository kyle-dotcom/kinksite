import os, secrets, json, urllib.request, pathlib
from datetime import datetime, timedelta

from dataclasses import dataclass
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, flash,
    render_template_string, session, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from flask_login import (
    LoginManager, UserMixin, login_user,
    current_user, login_required, logout_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from sqlalchemy.orm import selectinload, declared_attr
import secrets
              # + timedelta

# ---------- App ----------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "dev_"+secrets.token_hex(16))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///kinksite.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["WTF_CSRF_ENABLED"] = True
csrf = CSRFProtect(app)
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf}

# ---------- Models ----------


class PairScopedMixin:
    @declared_attr
    def pair_id(cls):
        # Keep nullable=True for easier backfill; set to False in a follow-up migration.
        return db.Column(db.Integer, db.ForeignKey("pair.id"), index=True, nullable=True)

    @declared_attr
    def pair(cls):
        return db.relationship("Pair", lazy="joined")


# ---------- Models ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "dom" or "sub"
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=True, index=True)
    # Points / progress
    points_total = db.Column(db.Integer, default=0)
    points_week  = db.Column(db.Integer, default=0)
    multiplier   = db.Column(db.Float, default=1.0)   # e.g., 1.0, 1.1, 1.2 …
    streak       = db.Column(db.Integer, default=0)

    # Preferences / notifications
    theme = db.Column(db.String(16), default="dark")        # "dark" | "light" | "system"
    time_format_24h = db.Column(db.Boolean, default=True)
    date_format = db.Column(db.String(16), default="YYYY-MM-DD")
    notify_lock_changes = db.Column(db.Boolean, default=True)
    notify_task_events  = db.Column(db.Boolean, default=True)

    # Pair link (user belongs to exactly one pair)
    pair_id = db.Column(db.Integer, db.ForeignKey("pair.id"), index=True)
    pair = db.relationship("Pair", backref="users")

    # Security: used for "log out all devices"
    session_nonce = db.Column(db.String(32), default="")
    @property
    def is_active(self) -> bool:  # Flask-Login checks this
        return bool(self.active)
    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)
    
    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Consent(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    agreed = db.Column(db.Boolean, default=False, index=True)
    safeword_yellow = db.Column(db.String(32), default="yellow")
    safeword_red = db.Column(db.String(32), default="red")
    agreed_at = db.Column(db.DateTime)


class Pair(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(16), unique=True, nullable=False,
                     default=lambda: secrets.token_hex(6))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)





# --- Profile + logs ---
class SubProfile(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, index=True, nullable=False)
    orgasm_policy = db.Column(db.String(20), default="allowed")  # allowed|denied|edging|ruined|custom
    last_orgasm_at = db.Column(db.DateTime, nullable=True)
    weight_kg = db.Column(db.Float, nullable=True)
    waist_cm = db.Column(db.Float, nullable=True)
    notes = db.Column(db.Text, default="")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    sub = db.relationship("User", lazy="joined")


class OrgasmEvent(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    kind = db.Column(db.String(16), default="allowed")  # allowed|denied|ruined|edge
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class BodyMetric(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    kind = db.Column(db.String(16), default="weight")   # weight|waist|hips|chest|bf
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(8), default="kg")        # kg|lb|cm|in|%
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)



class Rule(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    active = db.Column(db.Boolean, default=True, index=True)

    # NEW fields
    category = db.Column(db.String(40), default="general", index=True)
    severity = db.Column(db.Integer, default=2)              # 1–5
    penalty_points = db.Column(db.Integer, default=0)        # applied on violation
    requires_ack = db.Column(db.Boolean, default=True)
    active_from = db.Column(db.DateTime, nullable=True)
    active_until = db.Column(db.DateTime, nullable=True)
    sort_order = db.Column(db.Integer, default=0, index=True)

    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index("ix_rule_pair_created", "pair_id", "created_at"),
    )


class RuleAck(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rule.id"), index=True, nullable=False)
    sub_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    acked_at = db.Column(db.DateTime, default=datetime.utcnow)


class Task(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    points = db.Column(db.Integer, default=0)
    due_at = db.Column(db.DateTime, nullable=True, index=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"))  # sub id
    status = db.Column(db.String(20), default="open", index=True)  # open|done|verified
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.Index("ix_task_pair_created", "pair_id", "created_at"),
    )


class Punishment(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    # Keep your old points if you want to show it; it won’t affect anything.
    points = db.Column(db.Integer, default=0)

    # NEW
    category = db.Column(db.String(40), default="general", index=True)
    severity = db.Column(db.Integer, default=2)                        # 1–5 (1 minor … 5 severe)
    status   = db.Column(db.String(20), default="queued", index=True)  # queued|assigned|in_progress|completed|waived
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)

    acknowledged = db.Column(db.Boolean, default=False, index=True)
    acked_at = db.Column(db.DateTime, nullable=True)

    evidence_note = db.Column(db.Text, default="")
    evidence_url  = db.Column(db.String(255), default="")  # optional link (no upload yet)

    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.Index("ix_pun_pair_created", "pair_id", "created_at"),
    )


class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    pair_id = db.Column(db.Integer, db.ForeignKey("pair.id"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    target_role = db.Column(db.String(10), default="sub")   # only subs may accept
    max_uses = db.Column(db.Integer, default=1)             # 1 = single-use
    used_count = db.Column(db.Integer, default=0)
    expires_at = db.Column(db.DateTime, nullable=True)
    disabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    pair = db.relationship("Pair")
    creator = db.relationship("User", foreign_keys=[created_by])

    @staticmethod
    def gen_code():
        # Short, URL-safe and high entropy
        return secrets.token_urlsafe(16).rstrip("=").replace("_", "-")


class LockState(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    locked = db.Column(db.Boolean, default=False, index=True)
    unlock_at = db.Column(db.DateTime, nullable=True)
    emergency_pin_hash = db.Column(db.String(255), nullable=True)
    last_changed_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("pair_id", name="uq_lockstate_pair"),  # one lock state per pair
    )


class Journal(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sub_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    mood = db.Column(db.String(50))
    tags = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    locked = db.Column(db.Boolean, default=False, index=True)

    # relationship so e.comments works (newest first)
    comments = db.relationship(
        "JournalComment",
        backref="journal",
        lazy="selectin",
        order_by="desc(JournalComment.created_at)",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        db.Index("ix_journal_pair_created", "pair_id", "created_at"),
    )


class JournalComment(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    journal_id = db.Column(db.Integer, db.ForeignKey("journal.id"), nullable=False, index=True)
    dom_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # who commented
    dom = db.relationship("User", foreign_keys=[dom_id])


class CheckIn(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    mood = db.Column(db.String(30), default="")
    note = db.Column(db.Text, default="")
    # NEW
    energy = db.Column(db.Integer, default=None)        # 1–5
    sleep_hours = db.Column(db.Float, default=None)     # e.g., 6.5
    tags = db.Column(db.String(120), default="")        # comma-separated
    is_private = db.Column(db.Boolean, default=False)   # hide from Dom if True (still logged)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.Index("ix_checkin_pair_created", "pair_id", "created_at"),
    )


class Audit(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    action = db.Column(db.String(80), index=True)
    target = db.Column(db.String(80), index=True)
    details = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class PointsTxn(PairScopedMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    delta = db.Column(db.Integer, nullable=False)  # + or -
    reason = db.Column(db.String(120), default="", index=True)
    meta = db.Column(db.Text, default="")          # optional JSON-ish notes
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.Index("ix_points_pair_created", "pair_id", "created_at"),
    )



# ---------- Auth helpers ----------
@login_manager.user_loader
def load_user(uid): return User.query.get(int(uid))

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            if current_user.role not in roles:
                flash("Not allowed.")
                return redirect(url_for("dashboard"))
            return f(*a, **kw)
        return wrapper
    return decorator

def audit(actor_id, action, target, details=""):
    db.session.add(Audit(actor_id=actor_id, action=action, target=target, details=details))
    db.session.commit()

def get_lock():
    lock = LockState.query.order_by(LockState.id.desc()).first()
    if not lock:
        lock = LockState(locked=False)
        db.session.add(lock); db.session.commit()
    return lock

def add_points(user: User, delta: int, reason: str, meta: str = ""):
    """Apply points to a user and record a ledger row."""
    if not user or user.role != "sub":  # only sub accrues
        return
    user.points_total = (user.points_total or 0) + delta
    user.points_week  = (user.points_week  or 0) + delta
    db.session.add(PointsTxn(user_id=user.id, delta=delta, reason=reason, meta=meta))
    db.session.commit()
    audit(current_user.id if current_user.is_authenticated else None,
          "points", user.email, f"{delta} for {reason}")

def today_utc():
    return datetime.utcnow().date()

def get_sub():
    return User.query.filter_by(role="sub").first()


# ---- Formatting helpers (respect user settings) ----


# Parse a user-entered datetime string using their prefs (fallback: ISO)
def parse_user_datetime(s: str):
    s = (s or "").strip()
    if not s:
        return None
    try:
        df = _user_datefmt(current_user)   # e.g. "%d/%m/%Y"
        tf = _user_timefmt(current_user)   # e.g. "%H:%M" or "%I:%M %p"
        return datetime.strptime(s, f"{df} {tf}")
    except Exception:
        # allow ISO-ish forms too (supports "YYYY-MM-DD HH:MM" or "YYYY-MM-DDTHH:MM")
        try:
            return datetime.fromisoformat(s.replace("T", " "))
        except Exception:
            return None




def get_in_pair_or_404(model, object_id):
    obj = model.query.filter_by(id=object_id).first()
    if not obj or getattr(obj, "pair_id", None) != getattr(current_user, "pair_id", None):
        abort(404)
    return obj



def require_pair(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # assumes @login_required is also used, so user is authenticated here
        if not getattr(current_user, "pair_id", None):
            flash("Link with your partner to continue.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper





DATE_PATTERNS = {
    "YYYY-MM-DD": "%Y-%m-%d",
    "DD/MM/YYYY": "%d/%m/%Y",
    "MM/DD/YYYY": "%m/%d/%Y",
}

def _user_datefmt(user) -> str:
    fmt = (getattr(user, "date_format", None) or "YYYY-MM-DD")
    return DATE_PATTERNS.get(fmt, "%Y-%m-%d")

def _user_timefmt(user) -> str:
    # 24h => %H:%M, 12h => %I:%M %p
    is24 = getattr(user, "time_format_24h", True)
    return "%H:%M" if is24 else "%I:%M %p"

def fmt_dt(dt) -> str:
    """Format datetime per current_user’s preferences; returns '' if None."""
    if not dt: return ""
    try:
        df = _user_datefmt(current_user)
        tf = _user_timefmt(current_user)
        return dt.strftime(f"{df} {tf}")
    except Exception:
        return str(dt)



@app.template_filter("humandelta")
def humandelta(dt):
    if not dt:
        return "—"
    # using naive UTC to match the rest of your app
    delta = datetime.utcnow() - dt
    s = int(delta.total_seconds())
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    if d: return f"{d}d {h}h"
    if h: return f"{h}h {m}m"
    return f"{m}m"



def fmt_date(d) -> str:
    """Format a date/datetime as a date per user prefs."""
    if not d: return ""
    try:
        df = _user_datefmt(current_user)
        return (d.date() if hasattr(d, "date") else d).strftime(df)
    except Exception:
        return str(d)

def fmt_time(dt) -> str:
    """Format datetime/time per user prefs."""
    if not dt: return ""
    try:
        tf = _user_timefmt(current_user)
        return dt.strftime(tf)
    except Exception:
        return str(dt)

@app.context_processor
def inject_formatters():
    # expose helpers in Jinja
    return {
        "fmt_dt": fmt_dt,
        "fmt_date": fmt_date,
        "fmt_time": fmt_time,
    }

def model_has_column(model, col: str) -> bool:
    try:
        return col in model.__table__.columns
    except Exception:
        return False

def notify_discord(title: str, message: str, color=0x5865F2):
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {"embeds": [{"title": title, "description": message[:3900], "color": color}]}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(DISCORD_WEBHOOK_URL, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass

@app.template_filter("audit_meta")
def audit_meta(action: str):
    a = (action or "").lower()
    # label, ring/bg/text classes, icon
    if "login" in a:
        return {"label": "Login", "cls": "ring-sky-500/30 bg-sky-600/20 text-sky-300", "icon": "↪"}
    if "invite" in a:
        return {"label": "Invite", "cls": "ring-indigo-500/30 bg-indigo-600/20 text-indigo-300", "icon": "✉"}
    if "journal" in a or "comment" in a:
        return {"label": "Journal", "cls": "ring-fuchsia-500/30 bg-fuchsia-600/20 text-fuchsia-300", "icon": "📝"}
    if "task" in a:
        return {"label": "Task", "cls": "ring-blue-500/30 bg-blue-600/20 text-blue-300", "icon": "✔"}
    if "punish" in a:
        return {"label": "Punishment", "cls": "ring-rose-500/30 bg-rose-600/20 text-rose-300", "icon": "⛓"}
    if "rule" in a or "ack" in a:
        return {"label": "Rule", "cls": "ring-amber-500/30 bg-amber-600/20 text-amber-300", "icon": "⚖"}
    if "checkin" in a or "check-in" in a:
        return {"label": "Check-in", "cls": "ring-emerald-500/30 bg-emerald-600/20 text-emerald-300", "icon": "🌿"}
    if "lock" in a:
        return {"label": "Lock", "cls": "ring-purple-500/30 bg-purple-600/20 text-purple-300", "icon": "🔒"}
    if "points" in a or "txn" in a:
        return {"label": "Points", "cls": "ring-teal-500/30 bg-teal-600/20 text-teal-300", "icon": "💎"}
    if "unbind" in a or "reactivate" in a or "disable" in a:
        return {"label": "User", "cls": "ring-zinc-500/30 bg-zinc-700/40 text-zinc-200", "icon": "👤"}
    return {"label": "Event", "cls": "ring-zinc-500/30 bg-zinc-700/40 text-zinc-200", "icon": "•"}







# ---------- First-run guard ----------
@app.before_request
def require_dom_signup_first():
    # if no DOM exists, force /signup (except static/auth endpoints)
    has_dom = User.query.filter_by(role="dom").first() is not None
    allowed = {"signup", "login", "static"}
    if not has_dom and request.endpoint not in allowed:
        return redirect(url_for("signup"))


@app.before_request
def _disabled_and_nonce_guard():
    if not getattr(current_user, "is_authenticated", False):
        return
    # 1) Disabled accounts are logged out immediately
    if not current_user.is_active:
        logout_user()
        session.clear()
        flash("Your account has been disabled.")
        return redirect(url_for("login"))
    # 2) Invalidate old sessions when session_nonce changes
    if session.get("nonce") != getattr(current_user, "session_nonce", None):
        logout_user()
        session.clear()
        flash("Your session has expired. Please log in again.")
        return redirect(url_for("login"))
    
@app.before_request
def check_session_nonce():
    if current_user.is_authenticated:
        if session.get("nonce") != (current_user.session_nonce or ""):
            logout_user()
            return redirect(url_for("login"))


# ---------- Routes ----------
@app.route("/signup", methods=["GET","POST"])
def signup():
    # Only allowed if no dom exists yet
    if User.query.filter_by(role="dom").first():
        return redirect(url_for("login"))
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        name = request.form.get("name","").strip()
        pw = request.form.get("password","")
        if not (email and name and pw):
            flash("All fields required."); return redirect(url_for("signup"))
        if User.query.filter_by(email=email).first():
            flash("Email already exists."); return redirect(url_for("signup"))
        dom = User(email=email, name=name, role="dom")
        dom.set_password(pw)
        db.session.add(dom); db.session.commit()
        audit(dom.id, "create_user", email, "dom")
        login_user(dom)
        flash("Dom account created. You are logged in.")
        return redirect(url_for("dashboard"))
    return render_template_string(TPL["signup"])

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pw = request.form.get("password","")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(pw):
            if not (user.session_nonce or "").strip():
                user.session_nonce = secrets.token_hex(8)
                db.session.commit()

            login_user(user, remember=remember)
            session["nonce"] = user.session_nonce
            audit(user.id, "login", user.email, f"remember={int(remember)}")
            nxt = request.args.get("next")
            return redirect(nxt or url_for("dashboard"))

        flash("Invalid credentials.")

    return render_template_string(TPL["login"])


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



@app.route("/")
@login_required
def dashboard():
    lock = get_lock()

    # --- Lists (pair-scoped globally) ---
    rules = Rule.query.order_by(Rule.created_at.desc()).all()

    if current_user.role == "sub":
        open_tasks = (Task.query
                      .filter_by(assigned_to=current_user.id)
                      .order_by(Task.created_at.desc())
                      .all())
    else:
        open_tasks = (Task.query
                      .order_by(Task.created_at.desc())
                      .limit(10).all())

    punishments = (Punishment.query
                   .order_by(Punishment.created_at.desc())
                   .limit(10).all())

    # --- Consent (per-pair) ---
    consent = None
    if current_user.role == "sub":
        consent = Consent.query.filter_by(sub_id=current_user.id).first()
        if not consent:
            consent = Consent(sub_id=current_user.id, agreed=False, pair_id=current_user.pair_id)
            db.session.add(consent); db.session.commit()
    else:
        sub_for_consent = (User.query
                           .filter_by(pair_id=current_user.pair_id, role="sub")
                           .order_by(User.id.asc()).first())
        if sub_for_consent:
            consent = Consent.query.filter_by(sub_id=sub_for_consent.id).first()
            if not consent:
                consent = Consent(sub_id=sub_for_consent.id, agreed=False, pair_id=current_user.pair_id)
                db.session.add(consent); db.session.commit()

    # --- Stats for cards ---
    if current_user.role == "sub":
        tasks_active = Task.query.filter_by(assigned_to=current_user.id, status="open").count()
    else:
        tasks_active = Task.query.filter_by(status="open").count()

    punish_pending = Punishment.query.filter_by(status="queued").count()
    rules_count = Rule.query.count()

    # Ack pending for the current sub, considering active window
    rules_ack_pending = 0
    if current_user.role == "sub":
        acked_ids = {a.rule_id for a in RuleAck.query.filter_by(sub_id=current_user.id).all()}
        now = datetime.utcnow()
        active_window = and_(
            Rule.active.is_(True),
            or_(Rule.active_from.is_(None), Rule.active_from <= now),
            or_(Rule.active_until.is_(None), Rule.active_until >= now),
        )
        q_rules = Rule.query.filter(and_(Rule.requires_ack.is_(True), active_window))
        if acked_ids:
            q_rules = q_rules.filter(~Rule.id.in_(list(acked_ids)))
        rules_ack_pending = q_rules.count()

    # Last check-in for the viewer
    last_checkin = (CheckIn.query
                    .filter_by(user_id=current_user.id)
                    .order_by(CheckIn.created_at.desc())
                    .first())

    # --- Profile preview for dashboard card ---
    if current_user.role == "sub":
        sub_for_profile = current_user
    else:
        sub_for_profile = (User.query
                           .filter_by(pair_id=current_user.pair_id, role="sub")
                           .order_by(User.id.asc()).first())

    prof = None
    latest_weight = None
    if sub_for_profile:
        prof = SubProfile.query.filter_by(user_id=sub_for_profile.id).first()
        if prof:
            latest_weight = (BodyMetric.query
                             .filter_by(user_id=sub_for_profile.id, kind="weight")
                             .order_by(BodyMetric.created_at.desc())
                             .first())

    # --- Audit feed: filters (atype), search (q), show-more (limit) ---
    atype = (request.args.get("atype") or "all").lower()
    q = (request.args.get("q") or "").strip()
    try:
        limit = min(max(int(request.args.get("limit") or 20), 1), 200)
    except ValueError:
        limit = 20

    type_map = {
        "auth": "login",
        "invite": "invite",
        "journal": "journal",
        "task": "task",
        "punishment": "punish",
        "rule": "rule",
        "checkin": "check",
        "lock": "lock",
        "points": "points",
        "user": "unbind",
    }

    aq = Audit.query.order_by(Audit.created_at.desc())
    if atype != "all" and atype in type_map:
        aq = aq.filter(Audit.action.ilike(f"%{type_map[atype]}%"))
    if q:
        like = f"%{q}%"
        aq = aq.filter(or_(Audit.action.ilike(like),
                           Audit.target.ilike(like),
                           Audit.details.ilike(like)))
    history = aq.limit(limit).all()

    stats = {
        "tasks_active": tasks_active,
        "punishments_pending": punish_pending,
        "rules_count": rules_count,
        "rules_ack_pending": rules_ack_pending,
    }

    return render_template_string(
        TPL["dashboard"],
        lock=lock,
        rules=rules,
        tasks=open_tasks,
        punishments=punishments,
        consent=consent,
        stats=stats,
        last_checkin=last_checkin,
        history=history,
        atype=atype, q=q, limit=limit,          # for filter UI
        sub_for_profile=sub_for_profile,        # NEW: for profile card
        prof=prof, latest_weight=latest_weight  # NEW: for profile card
    )

@app.post("/pair/invite/new")
@login_required
def pair_invite_new():
    if current_user.role != "dom":
        abort(403)

    # Ensure DOM has a pair; if not, create one automatically
    if not current_user.pair_id:
        p = Pair(); db.session.add(p); db.session.flush()
        current_user.pair_id = p.id

    max_uses = int(request.form.get("max_uses") or 1)
    hours = request.form.get("expires_hours")
    expires_at = None
    if hours:
        try:
            h = int(hours)
            if h > 0:
                expires_at = datetime.utcnow() + timedelta(hours=h)
        except ValueError:
            pass

    inv = Invite(
        code=Invite.gen_code(),
        pair_id=current_user.pair_id,
        created_by=current_user.id,
        target_role="sub",
        max_uses=max(1, min(max_uses, 50)),
        expires_at=expires_at,
    )
    db.session.add(inv); db.session.commit()

    invite_url = url_for("pair_invite_view", code=inv.code, _external=True)
    flash(f"Invite created: {invite_url}")
    # optional audit
    try:
        audit(current_user.id, "invite_create", "invite", inv.code)
    except Exception:
        pass
    return redirect(url_for("dashboard"))

# --- View invite landing (must be logged in to accept) ---
@app.get("/i/<code>")
def pair_invite_view(code):
    inv = Invite.query.filter_by(code=code).first_or_404()
    if inv.disabled or (inv.expires_at and inv.expires_at < datetime.utcnow()) or inv.used_count >= inv.max_uses:
        flash("This invite link is no longer valid.")
        return redirect(url_for("login"))

    # compute a safe display label for the inviter
    creator = inv.creator
    creator_label = "Dom"
    if creator:
        creator_label = (
            getattr(creator, "username", None)
            or getattr(creator, "display_name", None)
            or getattr(creator, "name", None)
            or getattr(creator, "email", None)
            or "Dom"
        )

    can_direct_accept = (
        current_user.is_authenticated and
        getattr(current_user, "role", None) == "sub" and
        not getattr(current_user, "pair_id", None)
    )

    return render_template_string(
        TPL["invite"],
        invite=inv,
        can_direct_accept=can_direct_accept,
        creator_label=creator_label,
    )

@app.post("/i/<code>/accept")
def pair_invite_accept(code):
    inv = Invite.query.filter_by(code=code).with_for_update().first_or_404()
    if inv.disabled or (inv.expires_at and inv.expires_at < datetime.utcnow()) or inv.used_count >= inv.max_uses:
        flash("This invite link is no longer valid.")
        return redirect(url_for("login"))

    if not current_user.is_authenticated:
        flash("Please sign up below to accept this invite.")
        return redirect(url_for("pair_invite_signup", code=code))

    if getattr(current_user, "role", None) != "sub":
        flash("This invite is for a sub account. Please sign up a sub account.")
        return redirect(url_for("pair_invite_signup", code=code))

    if getattr(current_user, "pair_id", None):
        flash("Your account is already bound to a pair.")
        return redirect(url_for("dashboard"))

    current_user.pair_id = inv.pair_id
    inv.used_count += 1
    if inv.used_count >= inv.max_uses:
        inv.disabled = True
    db.session.commit()

    flash("You are now bound.")
    return redirect(url_for("dashboard"))

@app.route("/i/<code>/signup", methods=["GET", "POST"])
def pair_invite_signup(code):
    inv = Invite.query.filter_by(code=code).with_for_update().first_or_404()
    if inv.disabled or (inv.expires_at and inv.expires_at < datetime.utcnow()) or inv.used_count >= inv.max_uses:
        flash("This invite link is no longer valid.")
        return redirect(url_for("login"))

    supports_username = model_has_column(User, "username")
    supports_display_name = model_has_column(User, "display_name") or model_has_column(User, "name")

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        display_name = (request.form.get("display_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        # required
        if not email or not password:
            flash("Email and password are required.")
            return redirect(url_for("pair_invite_signup", code=code))

        # uniqueness (email always; username only if the column exists and a value was provided)
        if User.query.filter_by(email=email).first():
            flash("Email already in use.")
            return redirect(url_for("pair_invite_signup", code=code))

        if supports_username and username:
            if User.query.filter_by(username=username).first():
                flash("Username already in use.")
                return redirect(url_for("pair_invite_signup", code=code))

        # create user with only the fields your model supports
        u = User(
            email=email,
            password_hash=generate_password_hash(password),
            role="sub",
            pair_id=inv.pair_id,
        )
        if supports_username and username:
            setattr(u, "username", username)
        if supports_display_name and display_name:
            # prefer 'display_name' if present, else 'name'
            if model_has_column(User, "display_name"):
                setattr(u, "display_name", display_name)
            elif model_has_column(User, "name"):
                setattr(u, "name", display_name)

        db.session.add(u)
        inv.used_count += 1
        if inv.used_count >= inv.max_uses:
            inv.disabled = True
        db.session.commit()

        login_user(u)
        flash("Account created and bound.")
        try:
            audit(u.id, "invite_signup_accept", "invite", inv.code)
        except Exception:
            pass

        return redirect(url_for("dashboard"))

    # GET
    creator = inv.creator
    creator_label = "Dom"
    if creator:
        creator_label = (
            getattr(creator, "username", None)
            or getattr(creator, "display_name", None)
            or getattr(creator, "name", None)
            or getattr(creator, "email", None)
            or "Dom"
        )

    return render_template_string(
        TPL["invite_signup"],
        invite=inv,
        creator_label=creator_label,
        supports_username=supports_username,
        supports_display_name=supports_display_name,
    )
# --- Revoke invite (DOM who created it) ---
@app.post("/i/<code>/revoke")
@login_required
def pair_invite_revoke(code):
    inv = Invite.query.filter_by(code=code).first_or_404()
    if current_user.id != inv.created_by:
        abort(403)
    inv.disabled = True
    db.session.commit()
    flash("Invite revoked.")
    return redirect(url_for("dashboard"))

@app.route("/journal", methods=["GET","POST"])
@login_required
def journal_page():
    if request.method == "POST":
        if current_user.role == "sub":
            text = (request.form.get("content") or "").strip()
            mood = (request.form.get("mood") or "").strip()
            tags = (request.form.get("tags") or "").strip()
            if text:
                entry = Journal(sub_id=current_user.id, content=text, mood=mood, tags=tags)
                db.session.add(entry); db.session.commit()
                audit(current_user.id, "journal_create", "journal", text[:40])
                flash("Journal entry saved.")
        elif current_user.role == "dom":
            jid = int(request.form.get("jid") or 0)
            comment = (request.form.get("comment") or "").strip()
            if jid and comment:
                j = Journal.query.get_or_404(jid)
                c = JournalComment(journal_id=j.id, dom_id=current_user.id, content=comment)
                db.session.add(c); db.session.commit()
                audit(current_user.id, "journal_comment", "journal", f"jid={j.id} {comment[:40]}")
                flash("Comment added.")
        return redirect(url_for("journal_page"))

    # GET: load entries + comments + commenter efficiently
    q = (Journal.query
         .options(selectinload(Journal.comments).selectinload(JournalComment.dom))
         .order_by(Journal.created_at.desc()))

    # Sub should only see their own entries
    if current_user.role == "sub":
        q = q.filter_by(sub_id=current_user.id)

    entries = q.limit(50).all()
    return render_template_string(TPL["journal"], entries=entries)
# ---- Users (Dom creates Sub) ----
@app.route("/users", methods=["GET", "POST"])
@login_required
def users_page():
    # Only DOMs should touch this page; requires being paired
    if current_user.role != "dom":
        abort(403)
    if not current_user.pair_id:
        flash("Create an invite to start pairing.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()

        if action == "create_invite":
            max_uses = int(request.form.get("max_uses") or 1)
            hours = request.form.get("expires_hours")
            expires_at = None
            if hours:
                try:
                    h = int(hours)
                    if h > 0:
                        expires_at = datetime.utcnow() + timedelta(hours=h)
                except ValueError:
                    pass
            inv = Invite(
                code=Invite.gen_code(),
                pair_id=current_user.pair_id,
                created_by=current_user.id,
                target_role="sub",
                max_uses=max(1, min(max_uses, 50)),
                expires_at=expires_at,
            )
            db.session.add(inv); db.session.commit()
            flash("Invite created.", "success")
            return redirect(url_for("users_page"))

        elif action == "revoke_invite":
            code = (request.form.get("code") or "").strip()
            inv = Invite.query.filter_by(code=code, pair_id=current_user.pair_id).first()
            if not inv:
                flash("Invite not found.", "error")
            else:
                inv.disabled = True
                db.session.commit()
                flash("Invite revoked.", "success")
            return redirect(url_for("users_page"))

        elif action == "unbind_user":
              uid = int(request.form.get("uid") or 0)
              u = User.query.get(uid)
              if not u or u.pair_id != current_user.pair_id:
                  flash("User not in your pair.", "error")
              elif u.id == current_user.id:
                  flash("You can’t unbind yourself.", "error")
              else:
                  # hard cut-off
                  u.pair_id = None
                  u.active = False
                  u.session_nonce = secrets.token_hex(16)  # boots all sessions
                  db.session.commit()
                  flash("User unbound and disabled. They can no longer log in.", "success")
              return redirect(url_for("users_page"))

        elif action == "reactivate_user":
              uid = int(request.form.get("uid") or 0)
              u = User.query.get(uid)
              if not u or (u.pair_id and u.pair_id != current_user.pair_id):
                  flash("User not found.", "error")
              else:
                  u.active = True
                  u.session_nonce = secrets.token_hex(16)  # force fresh login
                  db.session.commit()
                  flash("User reactivated (not bound to a pair).", "success")
              return redirect(url_for("users_page"))

        elif action == "create_user":
            # Manual creation (bind to your pair)
            email = (request.form.get("email") or "").strip().lower()
            name = (request.form.get("name") or "").strip()
            role = (request.form.get("role") or "sub").strip()
            password = request.form.get("password") or ""
            if not email or not name or not password:
                flash("Email, name and password are required.", "error")
                return redirect(url_for("users_page"))
            if User.query.filter_by(email=email).first():
                flash("Email already exists.", "error")
                return redirect(url_for("users_page"))
            u = User(email=email, name=name, role=role, pair_id=current_user.pair_id)
            u.set_password(password)
            db.session.add(u); db.session.commit()
            flash("User created and bound to your pair.", "success")
            return redirect(url_for("users_page"))

        elif action == "reset":
            # Reset by email (restricted to users in your pair)
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            if not email or not password:
                flash("Email and new password required.", "error")
                return redirect(url_for("users_page"))
            u = User.query.filter_by(email=email).first()
            if not u or u.pair_id != current_user.pair_id:
                flash("User not found in your pair.", "error")
                return redirect(url_for("users_page"))
            u.set_password(password)
            db.session.commit()
            flash("Password updated.", "success")
            return redirect(url_for("users_page"))

    # GET
    members = User.query.filter_by(pair_id=current_user.pair_id).order_by(User.role.desc(), User.id.asc()).all()
    invites = (Invite.query
               .filter_by(pair_id=current_user.pair_id)
               .order_by(Invite.created_at.desc())
               .all())

    return render_template_string(TPL["users"], members=members, invites=invites, now=datetime.utcnow())


from math import isfinite
from flask import abort, request, redirect, url_for, flash, render_template_string

@app.route("/profile", methods=["GET", "POST"])
@login_required
@require_pair
def profile_page():
    # Which sub's profile are we looking at?
    if current_user.role == "sub":
        sub = current_user
        subs_for_dom = None
    else:
        uid = request.args.get("uid", type=int)
        q = User.query.filter_by(pair_id=current_user.pair_id, role="sub")
        subs_for_dom = q.order_by(User.name.asc(), User.id.asc()).all()
        if uid:
            sub = q.filter_by(id=uid).first()
            if not sub:
                abort(404)
        else:
            sub = subs_for_dom[0] if subs_for_dom else None
            if not sub:
                flash("No subs in this pair yet.", "error")
                return redirect(url_for("users_page"))

    # Ensure profile exists
    prof = SubProfile.query.filter_by(user_id=sub.id).first()
    if not prof:
        prof = SubProfile(user_id=sub.id, pair_id=sub.pair_id)
        db.session.add(prof); db.session.commit()

    # ---- Only the sub (owner) may POST/update ----
    if request.method == "POST":
        if current_user.role != "sub" or sub.id != current_user.id:
            abort(403)

        action = (request.form.get("action") or "").strip()

        if action == "save_profile":
            prof.orgasm_policy = (request.form.get("orgasm_policy") or prof.orgasm_policy or "allowed").strip()
            prof.notes = (request.form.get("notes") or "").strip()

            w = (request.form.get("weight_kg") or "").strip()
            if w:
                try:
                    val = float(w); prof.weight_kg = val
                    db.session.add(BodyMetric(user_id=sub.id, kind="weight", value=val, unit="kg",
                                              pair_id=current_user.pair_id))
                except ValueError:
                    flash("Weight must be a number.", "error")

            waist = (request.form.get("waist_cm") or "").strip()
            if waist:
                try:
                    val = float(waist); prof.waist_cm = val
                    db.session.add(BodyMetric(user_id=sub.id, kind="waist", value=val, unit="cm",
                                              pair_id=current_user.pair_id))
                except ValueError:
                    flash("Waist must be a number.", "error")

            db.session.commit()
            try: audit(current_user.id, "profile_update", "profile", f"sub={sub.id}")
            except Exception: pass
            flash("Profile updated.", "success")
            return redirect(url_for("profile_page"))

        elif action == "log_orgasm":
            ev = OrgasmEvent(user_id=sub.id, kind="allowed", pair_id=current_user.pair_id)
            prof.last_orgasm_at = ev.created_at
            db.session.add(ev); db.session.commit()
            try: audit(current_user.id, "orgasm_log", "profile", f"sub={sub.id}")
            except Exception: pass
            flash("Orgasm logged.", "success")
            return redirect(url_for("profile_page"))

        elif action == "log_denial":
            ev = OrgasmEvent(user_id=sub.id, kind="denied", pair_id=current_user.pair_id)
            db.session.add(ev); db.session.commit()
            try: audit(current_user.id, "orgasm_denied", "profile", f"sub={sub.id}")
            except Exception: pass
            flash("Denial logged.", "success")
            return redirect(url_for("profile_page"))

    # ---- Fetch recent logs for display ----
    events = (OrgasmEvent.query
              .filter_by(user_id=sub.id)
              .order_by(OrgasmEvent.created_at.desc())
              .limit(10).all())
    metrics = (BodyMetric.query
               .filter_by(user_id=sub.id)
               .order_by(BodyMetric.created_at.desc())
               .limit(10).all())

    # ---- Derived stats for nicer UI ----
    # Days since last orgasm
    days_since = None
    if prof.last_orgasm_at:
        try:
            days_since = max(0, (datetime.utcnow() - prof.last_orgasm_at).days)
        except Exception:
            days_since = None

    # Metric summaries (sparklines etc.)
    def metric_summary(kind: str, unit: str, n=24, svg_w=160, svg_h=40, pad=4):
        series = (BodyMetric.query
                  .filter_by(user_id=sub.id, kind=kind)
                  .order_by(BodyMetric.created_at.asc())
                  .limit(n).all())
        latest = series[-1] if series else None
        prev = series[-2] if len(series) > 1 else None
        delta = None
        if latest and prev and isfinite(latest.value) and isfinite(prev.value):
            delta = latest.value - prev.value

        points = ""
        if series and len(series) >= 2:
            vals = [m.value for m in series]
            vmin, vmax = min(vals), max(vals)
            vrange = (vmax - vmin) or 1.0
            step = (svg_w - 2*pad) / (len(vals) - 1)
            pts = []
            for i, v in enumerate(vals):
                x = pad + i * step
                y = pad + (vmax - v) * (svg_h - 2*pad) / vrange
                pts.append(f"{x:.1f},{y:.1f}")
            points = " ".join(pts)

        return {"latest": latest, "prev": prev, "delta": delta,
                "points": points, "unit": unit, "svg_w": svg_w, "svg_h": svg_h}

    weight_summary = metric_summary("weight", "kg")
    waist_summary  = metric_summary("waist", "cm", svg_w=160, svg_h=40)

    # ---- Orgasm counters (and 7-day mini stats) ----
    now = datetime.utcnow()
    sod = now.replace(hour=0, minute=0, second=0, microsecond=0)       # start of today UTC
    sow = sod - timedelta(days=sod.weekday())                          # Monday 00:00 UTC
    som = sod.replace(day=1)                                           # 1st of month 00:00 UTC

    allowed_q = OrgasmEvent.query.filter_by(user_id=sub.id, kind="allowed")
    orgasms_today = allowed_q.filter(OrgasmEvent.created_at >= sod).count()
    orgasms_week  = allowed_q.filter(OrgasmEvent.created_at >= sow).count()
    orgasms_month = allowed_q.filter(OrgasmEvent.created_at >= som).count()

    since_7 = now - timedelta(days=7)
    allowed_7d = allowed_q.filter(OrgasmEvent.created_at >= since_7).count()
    denied_7d  = (OrgasmEvent.query
                  .filter_by(user_id=sub.id, kind="denied")
                  .filter(OrgasmEvent.created_at >= since_7).count())

    return render_template_string(
        TPL["profile"],
        sub=sub, prof=prof,
        events=events, metrics=metrics,
        subs=subs_for_dom,
        days_since=days_since,
        weight_summary=weight_summary, waist_summary=waist_summary,
        allowed_7d=allowed_7d, denied_7d=denied_7d,
        orgasms_today=orgasms_today, orgasms_week=orgasms_week, orgasms_month=orgasms_month,
    )





# ---- Rules ----
@app.route("/rules", methods=["GET","POST"])
@login_required
def rules_page():
    # --- Create / Edit / Ack actions ---
    if request.method == "POST":
        action = request.form.get("action", "")

        # SUB: acknowledge visible rules
        if current_user.role == "sub" and action == "ack_all":
            sub = current_user
            # acknowledge all active, in-date rules that require ack
            now = datetime.now()
            q = Rule.query.filter(
                Rule.active.is_(True),
                db.or_(Rule.active_from.is_(None), Rule.active_from <= now),
                db.or_(Rule.active_until.is_(None), Rule.active_until >= now),
                Rule.requires_ack.is_(True)
            )
            rules_to_ack = q.all()
            for r in rules_to_ack:
                if not RuleAck.query.filter_by(rule_id=r.id, sub_id=sub.id).first():
                    db.session.add(RuleAck(rule_id=r.id, sub_id=sub.id))
            db.session.commit()
            audit(sub.id, "ack_rules", "rules", f"count={len(rules_to_ack)}")
            flash("Acknowledged current rules.")
            return redirect(url_for("rules_page"))

        # DOM: create / update
        if current_user.role != "dom":
            flash("Only Dom can modify rules."); return redirect(url_for("rules_page"))

        # Create
        if action == "create":
            title = (request.form.get("title") or "").strip()
            if not title:
                flash("Title is required."); return redirect(url_for("rules_page"))
            desc = (request.form.get("description") or "").strip()
            category = (request.form.get("category") or "general").strip().lower()
            severity = int(request.form.get("severity") or 2)
            penalty = int(request.form.get("penalty_points") or 0)
            requires_ack = bool(request.form.get("requires_ack"))
            afrom = (request.form.get("active_from") or "").strip()
            auntil = (request.form.get("active_until") or "").strip()
            active_from = datetime.fromisoformat(afrom) if afrom else None
            active_until = datetime.fromisoformat(auntil) if auntil else None

            # sort_order = max+1
            max_order = db.session.query(db.func.coalesce(db.func.max(Rule.sort_order), 0)).scalar()
            r = Rule(
                title=title, description=desc, category=category,
                severity=max(1, min(5, severity)), penalty_points=penalty,
                requires_ack=requires_ack, active_from=active_from, active_until=active_until,
                active=True, sort_order=max_order + 1, created_by=current_user.id
            )
            db.session.add(r); db.session.commit()
            audit(current_user.id, "create", "rule", title)
            flash("Rule added.")
            return redirect(url_for("rules_page"))

        # Update inline
        if action == "update":
            rid = int(request.form.get("id"))
            r = Rule.query.get_or_404(rid)
            r.title = (request.form.get("title") or r.title).strip()
            r.description = (request.form.get("description") or r.description).strip()
            r.category = (request.form.get("category") or r.category).strip().lower()
            r.severity = max(1, min(5, int(request.form.get("severity") or r.severity)))
            r.penalty_points = int(request.form.get("penalty_points") or r.penalty_points)
            r.requires_ack = bool(request.form.get("requires_ack"))  # checkbox on sends value
            afrom = (request.form.get("active_from") or "").strip()
            auntil = (request.form.get("active_until") or "").strip()
            r.active_from = datetime.fromisoformat(afrom) if afrom else None
            r.active_until = datetime.fromisoformat(auntil) if auntil else None
            r.updated_at = datetime.utcnow()
            db.session.commit()
            audit(current_user.id, "update", "rule", r.title)
            flash("Rule updated.")
            return redirect(url_for("rules_page"))

    # --- Read / Filters ---
    view = (request.args.get("view") or "active").lower()  # active | all
    category = (request.args.get("cat") or "").strip().lower()
    q = Rule.query
    if view == "active":
        now = datetime.now()
        q = q.filter(
            Rule.active.is_(True),
            db.or_(Rule.active_from.is_(None), Rule.active_from <= now),
            db.or_(Rule.active_until.is_(None), Rule.active_until >= now),
        )
    if category:
        q = q.filter(Rule.category == category)
    rules = q.order_by(Rule.sort_order.asc(), Rule.created_at.desc()).all()

    # ack map (for sub)
    acked_ids = set()
    if current_user.role == "sub":
        rows = RuleAck.query.filter_by(sub_id=current_user.id).all()
        acked_ids = {r.rule_id for r in rows}

    # categories list for filter
    cats = [c[0] for c in db.session.query(Rule.category).distinct().all()]
    cats = sorted(set(cats + ["general"]))

    return render_template_string(TPL["rules"], rules=rules, cats=cats, view=view, category=category, acked_ids=acked_ids)

@app.route("/rules/<int:rid>/toggle")
@role_required("dom")
def rule_toggle(rid):
    r = Rule.query.get_or_404(rid)
    r.active = not r.active; db.session.commit()
    audit(current_user.id, "toggle", "rule", f"{r.title} -> {r.active}")
    return redirect(url_for("rules_page"))


@app.route("/rules/<int:rid>/reorder/<string:direction>", methods=["POST"])
@role_required("dom")
def rule_reorder(rid, direction):
    r = Rule.query.get_or_404(rid)
    if direction not in ("up", "down"):
        return redirect(url_for("rules_page"))
    neighbor = (Rule.query
        .filter(Rule.id != r.id)
        .order_by(Rule.sort_order.asc() if direction=="up" else Rule.sort_order.desc())
        .first())
    if neighbor:
        r.sort_order, neighbor.sort_order = neighbor.sort_order, r.sort_order
        db.session.commit()
        audit(current_user.id, "reorder", "rule", f"{r.title} {direction}")
    return redirect(url_for("rules_page"))

@app.route("/rules/<int:rid>/delete", methods=["POST"])
@role_required("dom")
def rule_delete(rid):
    r = Rule.query.get_or_404(rid)
    title = r.title
    db.session.delete(r); db.session.commit()
    audit(current_user.id, "delete", "rule", title)
    flash("Rule deleted.")
    return redirect(url_for("rules_page"))

# ---- Tasks ----
@app.route("/tasks", methods=["GET","POST"])
@login_required
def tasks_page():
    # Default sub = first sub (single couple); adjust as needed
    sub = User.query.filter_by(role="sub").first()
    if request.method == "POST" and current_user.role=="dom":
        if not sub:
            flash("Create a Sub user first."); return redirect(url_for("users_page"))
        title = request.form.get("title","").strip()
        desc = request.form.get("description","").strip()
        points = int(request.form.get("points","0") or 0)
        due = request.form.get("due_at","").strip()
        due_at = datetime.fromisoformat(due) if due else None
        t = Task(title=title, description=desc, points=points, due_at=due_at, assigned_to=sub.id)
        db.session.add(t); db.session.commit()
        audit(current_user.id, "create", "task", title)
        flash("Task created.")
    tasks = Task.query.order_by(Task.created_at.desc()).all() if current_user.role=="dom" else Task.query.filter_by(assigned_to=current_user.id).all()
    return render_template_string(TPL["tasks"], tasks=tasks)

@app.route("/tasks/<int:tid>/complete", methods=["POST"])
@role_required("sub")
def task_complete(tid):
    t = Task.query.get_or_404(tid)
    if t.assigned_to != current_user.id: 
        flash("Not your task."); return redirect(url_for("tasks_page"))
    t.status = "done"; db.session.commit()
    audit(current_user.id, "complete", "task", t.title)
    return redirect(url_for("tasks_page"))

@app.route("/tasks/<int:tid>/verify")
@role_required("dom")
def task_verify(tid):
    t = Task.query.get_or_404(tid)
    t.status = "verified"; db.session.commit()

    sub = User.query.filter_by(id=t.assigned_to, role="sub").first()
    if sub:
        # Streak logic: if user had a verified task today, keep; if yesterday, +1; else reset.
        last_txn = PointsTxn.query.filter_by(user_id=sub.id).order_by(PointsTxn.created_at.desc()).first()
        last_day = last_txn.created_at.date() if last_txn else None
        if last_day == today_utc():
            pass
        elif last_day == today_utc() - timedelta(days=1):

            sub.streak = (sub.streak or 0) + 1
        else:
            sub.streak = 1

        # Multiplier: base 1.0 + 0.02 per streak up to +20% (cap).
        sub.multiplier = min(1.0 + 0.02 * (sub.streak - 1), 1.20)

        base = t.points or 0
        award = int(round(base * (sub.multiplier or 1.0)))
        db.session.commit()

        add_points(sub, award, reason=f"Task verified: {t.title}", meta=f"base={base},mult={sub.multiplier:.2f},streak={sub.streak}")

    audit(current_user.id, "verify", "task", t.title)
    flash("Task verified and points awarded.")
    return redirect(url_for("tasks_page"))


# ---- Punishments ----
@app.route("/punishments", methods=["GET","POST"])
@login_required
def punishments_page():
    # ---- Create / Actions ----
    if request.method == "POST":
        action = request.form.get("action","")

        # Sub actions
        if current_user.role == "sub":
            pid = int(request.form.get("pid","0") or 0)
            p = Punishment.query.get_or_404(pid)
            if p.assigned_to and p.assigned_to != current_user.id:
                flash("Not allowed."); return redirect(url_for("punishments_page"))

            if action == "ack":
                if not p.acknowledged:
                    p.acknowledged = True
                    p.acked_at = datetime.utcnow()
                    if p.status == "assigned":
                        p.status = "in_progress"
                    p.updated_at = datetime.utcnow()
                    db.session.commit()
                    audit(current_user.id, "ack_punishment", "punishment", p.title)
                    flash("Acknowledged.")
                return redirect(url_for("punishments_page"))

            if action == "complete":
                note = (request.form.get("evidence_note") or "").strip()
                url  = (request.form.get("evidence_url")  or "").strip()
                p.evidence_note = note
                p.evidence_url  = url
                p.status = "completed"
                p.updated_at = datetime.utcnow()
                db.session.commit()
                audit(current_user.id, "complete_punishment", "punishment", f"{p.title} note_len={len(note)}")
                flash("Submitted as completed.")
                return redirect(url_for("punishments_page"))

            flash("Unknown action."); return redirect(url_for("punishments_page"))

        # Dom actions
        if current_user.role != "dom":
            flash("Only Dom can manage punishments."); return redirect(url_for("punishments_page"))

        if action == "create":
            title = (request.form.get("title") or "").strip()
            if not title:
                flash("Title is required."); return redirect(url_for("punishments_page"))
            desc = (request.form.get("description") or "").strip()
            category = (request.form.get("category") or "general").strip().lower()
            severity = max(1, min(5, int(request.form.get("severity") or 2)))

            sub = User.query.filter_by(role="sub").first()
            p = Punishment(
                title=title, description=desc,
                category=category, severity=severity,
                status="assigned" if sub else "queued",
                assigned_to=sub.id if sub else None,
                created_by=current_user.id
            )
            db.session.add(p); db.session.commit()
            audit(current_user.id, "queue", "punishment", title)
            flash("Punishment queued.")
            return redirect(url_for("punishments_page"))

        if action == "status":
            pid = int(request.form.get("pid","0") or 0)
            state = (request.form.get("state") or "queued").strip()
            if state not in ("queued","assigned","in_progress","completed","waived"):
                state = "queued"
            p = Punishment.query.get_or_404(pid)
            p.status = state
            p.updated_at = datetime.utcnow()
            db.session.commit()
            audit(current_user.id, "status", "punishment", f"{p.title} -> {state}")
            flash("Status updated.")
            return redirect(url_for("punishments_page"))

        if action == "escalate":
            pid = int(request.form.get("pid","0") or 0)
            base = Punishment.query.get_or_404(pid)
            new = Punishment(
                title=f"Escalation: {base.title}",
                description=f"Escalated due to delay/defiance. Original: {base.id}",
                category=base.category,
                severity=min(5, (base.severity or 2) + 1),
                status="assigned",
                assigned_to=base.assigned_to,
                created_by=current_user.id
            )
            db.session.add(new); db.session.commit()
            audit(current_user.id, "escalate", "punishment", f"{base.title} -> {new.severity}")
            flash("Escalated.")
            return redirect(url_for("punishments_page"))

    # ---- Filters / Stats ----
    view = (request.args.get("view") or "pending").lower()   # pending|all|mine
    cat  = (request.args.get("cat") or "").strip().lower()
    status_filter = (request.args.get("status") or "").strip().lower()  # optional extra status filter

    q = Punishment.query
    if view == "pending":
        q = q.filter(Punishment.status.in_(["queued","assigned","in_progress"]))
    elif view == "mine":
        q = q.filter(Punishment.assigned_to == current_user.id)

    if cat:
        q = q.filter(Punishment.category == cat)
    if status_filter in ("queued","assigned","in_progress","completed","waived"):
        q = q.filter(Punishment.status == status_filter)

    items = q.order_by(
        db.case((Punishment.status=="in_progress", 0),
                (Punishment.status=="assigned", 1),
                (Punishment.status=="queued", 2),
                (Punishment.status=="completed", 3),
                (Punishment.status=="waived", 4), else_=5),
        Punishment.created_at.desc()
    ).limit(200).all()

    total = Punishment.query.count()
    pending = Punishment.query.filter(Punishment.status.in_(["queued","assigned","in_progress"])).count()
    completed = Punishment.query.filter_by(status="completed").count()
    waived = Punishment.query.filter_by(status="waived").count()
    avg_time = None
    done = Punishment.query.filter(Punishment.status=="completed", Punishment.acked_at.isnot(None)).all()
    if done:
        spans = []
        for d in done:
            end = d.updated_at or d.created_at
            start = d.acked_at or d.created_at
            spans.append((end - start).total_seconds()/3600.0)
        if spans:
            avg_time = sum(spans)/len(spans)

    cats = [c[0] for c in db.session.query(Punishment.category).distinct().all()]
    cats = sorted(set(cats + ["general"]))

    return render_template_string(
        TPL["punishments"],
        items=items, total=total, pending=pending, completed=completed, waived=waived,
        avg_time=avg_time, cats=cats, view=view, cat=cat, status_filter=status_filter
    )





# ---- Lock / Chastity timer ----
@app.route("/lock", methods=["GET","POST"])
@login_required
def lock_page():
    lock = get_lock()
    now = datetime.now()  # keep naive to match fromisoformat (no tz)

    if request.method == "POST":
        # Sub can only request
        if current_user.role == "sub":
            if "request_release" in request.form:
                note = request.form.get("note", "")
                audit(current_user.id, "request_release", "lock", note)
                notify_discord("Early Release Requested", f"{current_user.name} requested early release: {note}", 0x3498DB)
                flash("Release request sent (logged).")
            else:
                flash("Only Dom can change the lock.")
            return redirect(url_for("lock_page"))

        # ---- Dom controls ----
        action = request.form.get("action", "")

        if action == "lock_set":
            raw = request.form.get("unlock_at", "").strip()
            dt = parse_user_datetime(raw)
            lock.locked = True
            lock.unlock_at = dt


        elif action == "lock_quick":
            mins = int(request.form.get("quick_minutes", "0") or 0)
            if mins > 0:
                base = lock.unlock_at if (lock.locked and lock.unlock_at and lock.unlock_at > now) else now
                lock.locked = True
                lock.unlock_at = base + timedelta(minutes=mins)

        elif action == "add_time":
            mins = int(request.form.get("add_minutes", "0") or 0)
            if mins != 0:
                base = lock.unlock_at if lock.unlock_at else now
                lock.locked = True
                lock.unlock_at = base + timedelta(minutes=mins)

        elif action == "unlock":
            lock.locked = False
            lock.unlock_at = None

        elif action == "lock":
            lock.locked = True

        # Update emergency PIN if provided (applies on any POST)
        pin = (request.form.get("emergency_pin") or "").strip()
        if pin:
            lock.emergency_pin_hash = generate_password_hash(pin)

        lock.last_changed_by = current_user.id
        lock.updated_at = datetime.now()  # naive to match DB
        db.session.commit()

        state = "LOCKED" if lock.locked else "UNLOCKED"
        until_txt = f" until {lock.unlock_at}" if lock.unlock_at else ""
        notify_discord("Lock State Changed", f"{current_user.name} set lock → {state}{until_txt}", 0x95A5A6)
        audit(current_user.id, action or ("lock" if lock.locked else "unlock"), "lock", f"unlock_at={lock.unlock_at}")
        flash(f"Lock updated: {state}.")
        return redirect(url_for("lock_page"))

    # recent history
    history = Audit.query.filter(
        Audit.action.in_(["lock", "unlock", "request_release", "safeword_red", "emergency_release"])
    ).order_by(Audit.created_at.desc()).limit(12).all()

    # precompute remaining seconds for the template (avoid using datetime in Jinja)
    remaining = None
    if lock.unlock_at:
        remaining = max(0, int((lock.unlock_at - now).total_seconds()))

    return render_template_string(TPL["lock"], lock=lock, history=history, remaining=remaining, now_dt=datetime.now())


# ---- Safeword & Emergency ----
@app.route("/safeword", methods=["POST"])
@role_required("sub")
def safeword():
    word = request.form.get("word","").lower().strip()
    consent = Consent.query.filter_by(sub_id=current_user.id).first()
    if not consent:
        flash("Consent record missing."); return redirect(url_for("dashboard"))
    lock = get_lock()
    if word == consent.safeword_yellow.lower():
        audit(current_user.id, "safeword_yellow", "session", "")
        notify_discord("Safeword: YELLOW", f"{current_user.name} signaled YELLOW. Please adjust.", 0xF1C40F)
        flash("Yellow acknowledged.")
    elif word == consent.safeword_red.lower():
        lock.locked = False; lock.unlock_at = None
        lock.updated_at = datetime.now()
        db.session.commit()
        audit(current_user.id, "safeword_red", "lock", "Auto-unlocked.")
        notify_discord("Safeword: RED", f"{current_user.name} triggered RED. Lock auto-unlocked.", 0xE74C3C)
        flash("RED safeword: lock auto-unlocked and logged.")
    else:
        flash("Unknown safeword.")
    return redirect(url_for("dashboard"))

@app.route("/emergency", methods=["POST"])
@role_required("sub")
def emergency():
    pin = request.form.get("pin","")
    lock = get_lock()
    if not lock.emergency_pin_hash:
        flash("No emergency PIN set."); return redirect(url_for("dashboard"))
    if check_password_hash(lock.emergency_pin_hash, pin):
        lock.locked = False; lock.unlock_at = None
        lock.updated_at = datetime.now()
        db.session.commit()
        audit(current_user.id, "emergency_release", "lock", "PIN OK")
        notify_discord("Emergency Release", f"{current_user.name} used the emergency PIN. Lock opened.", 0xE74C3C)
        flash("Emergency release processed and logged.")
    else:
        audit(current_user.id, "emergency_pin_fail", "lock", "")
        notify_discord("Emergency PIN Failed", f"{current_user.name} provided a wrong PIN.", 0xE67E22)
        flash("Incorrect emergency PIN.")
    return redirect(url_for("dashboard"))

# ---- Check-ins ----
@app.route("/checkins", methods=["GET","POST"])
@login_required
def checkins():
    # Create
    if request.method == "POST":
        mood = (request.form.get("mood","") or "").strip()
        note = (request.form.get("note","") or "").strip()
        energy = request.form.get("energy")
        sleep = request.form.get("sleep_hours")
        tags = (request.form.get("tags","") or "").strip()
        is_private = bool(request.form.get("is_private"))

        try:
            energy = int(energy) if energy not in (None, "",) else None
            if energy is not None: energy = max(1, min(5, energy))
        except Exception:
            energy = None
        try:
            sleep_hours = float(sleep) if sleep not in (None, "",) else None
        except Exception:
            sleep_hours = None

        db.session.add(CheckIn(
            user_id=current_user.id,
            mood=mood, note=note,
            energy=energy, sleep_hours=sleep_hours,
            tags=tags, is_private=is_private
        ))
        db.session.commit()
        audit(current_user.id, "checkin", "status", f"{mood} e={energy} s={sleep_hours} tags={tags} private={is_private}")
        return redirect(url_for("checkins"))

    # Read with filters
    rng = (request.args.get("range") or "7d").lower()  # 7d | 30d | all
    q = CheckIn.query

    # Privacy: Dom cannot see private entries; Sub can see all their own
    if current_user.role == "dom":
        # show only the Sub's non-private entries
        sub = User.query.filter_by(role="sub").first()
        if sub:
            q = q.filter(CheckIn.user_id == sub.id, CheckIn.is_private.is_(False))
        else:
            q = q.filter(CheckIn.user_id == -1)
    else:
        q = q.filter(CheckIn.user_id == current_user.id)

    if rng != "all":
        days = 7 if rng == "7d" else 30
        since = datetime.utcnow() - timedelta(days=days)
        q = q.filter(CheckIn.created_at >= since)

    items = q.order_by(CheckIn.created_at.desc()).limit(200).all()

    # Simple stats (visible at top)
    total = len(items)
    mood_counts = {}
    energy_vals, sleep_vals = [], []
    for c in items:
        if c.mood:
            mood_counts[c.mood] = mood_counts.get(c.mood, 0) + 1
        if c.energy is not None:
            energy_vals.append(c.energy)
        if c.sleep_hours is not None:
            sleep_vals.append(c.sleep_hours)

    stats = {
        "total": total,
        "moods": sorted(mood_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5],
        "avg_energy": (sum(energy_vals)/len(energy_vals)) if energy_vals else None,
        "avg_sleep": (sum(sleep_vals)/len(sleep_vals)) if sleep_vals else None,
    }

    return render_template_string(TPL["checkins"], items=items, stats=stats, rng=rng)

@app.route("/checkins/<int:cid>/delete", methods=["POST"])
@login_required
def checkin_delete(cid):
    c = CheckIn.query.get_or_404(cid)
    if current_user.role == "dom":
        # Dom may delete only sub's non-private entries
        sub = User.query.filter_by(role="sub").first()
        if not sub or c.user_id != sub.id:
            flash("Not allowed."); return redirect(url_for("checkins"))
    else:
        if c.user_id != current_user.id:
            flash("Not allowed."); return redirect(url_for("checkins"))
    db.session.delete(c); db.session.commit()
    audit(current_user.id, "delete_checkin", "status", f"id={cid}")
    return redirect(url_for("checkins"))


# ---- Consent ----
@app.route("/consent", methods=["GET","POST"])
@login_required
def consent_page():
    if current_user.role != "sub":
        # show the first sub's consent if dom
        sub = User.query.filter_by(role="sub").first()
        if not sub:
            flash("Create a Sub user first."); return redirect(url_for("users_page"))
        c = Consent.query.filter_by(sub_id=sub.id).first()
    else:
        c = Consent.query.filter_by(sub_id=current_user.id).first()
        if not c:
            c = Consent(sub_id=current_user.id, agreed=False); db.session.add(c); db.session.commit()

    if request.method == "POST" and current_user.role=="sub":
        c.agreed = True
        c.safeword_yellow = request.form.get("yellow","yellow").strip() or "yellow"
        c.safeword_red = request.form.get("red","red").strip() or "red"
        c.agreed_at = datetime.utcnow()
        db.session.commit(); audit(current_user.id, "consent_agree", "consent", "")
        flash("Consent saved.")
        return redirect(url_for("dashboard"))
    return render_template_string(TPL["consent"], c=c)

@app.route("/leaderboard")
@login_required
def leaderboard():
    top = User.query.filter_by(role="sub").order_by(User.points_week.desc()).limit(25).all()
    return render_template_string(TPL["leaderboard"], users=top)

@app.route("/close_week", methods=["POST"])
@role_required("dom")
def close_week():
    sub = User.query.filter_by(role="sub").first()
    if sub:
        audit(current_user.id, "close_week", sub.email, f"weekly={sub.points_week}")
        # optional: also log into ledger as meta-only row
        db.session.add(PointsTxn(user_id=sub.id, delta=0, reason="WEEK_CLOSE", meta=f"weekly={sub.points_week}"))
        sub.points_week = 0
        db.session.commit()
        flash("Week closed. Weekly points reset.")
    return redirect(url_for("leaderboard"))



@app.route("/settings", methods=["GET","POST"])
@login_required
def settings_page():
    if request.method == "POST":
        # Change password form
        if request.form.get("change_password") == "1":
            cur = request.form.get("current","")
            new = request.form.get("new","")
            confirm = request.form.get("confirm","")
            if not current_user.check_password(cur):
                flash("Current password is wrong."); return redirect(url_for("settings_page"))
            if not new or new != confirm:
                flash("New passwords don’t match."); return redirect(url_for("settings_page"))
            current_user.set_password(new)
            db.session.commit()
            audit(current_user.id, "change_password", current_user.email, "")
            flash("Password updated.")
            return redirect(url_for("settings_page"))

        # Profile + preferences form
        name   = (request.form.get("name") or "").strip()
        email  = (request.form.get("email") or "").strip().lower()
        theme  = request.form.get("theme") or "dark"
        datefmt = request.form.get("date_format") or "YYYY-MM-DD"
        time24 = bool(request.form.get("time_format_24h"))
        n_lock = bool(request.form.get("notify_lock_changes"))
        n_task = bool(request.form.get("notify_task_events"))

        if email and email != current_user.email:
            if User.query.filter_by(email=email).first():
                flash("That email is already in use.")
                return redirect(url_for("settings_page"))
            current_user.email = email

        if name: current_user.name = name
        current_user.theme = theme
        current_user.date_format = datefmt
        current_user.time_format_24h = time24
        current_user.notify_lock_changes = n_lock
        current_user.notify_task_events  = n_task

        # Log out all devices
        if request.form.get("logout_all") == "1":
            current_user.session_nonce = secrets.token_hex(8)
            # keep THIS browser logged in
            session["nonce"] = current_user.session_nonce
            flash("All other devices have been logged out.")

        db.session.commit()
        audit(current_user.id, "update_settings", current_user.email, f"theme={theme}")
        if request.form.get("logout_all") != "1":
            flash("Settings saved.")
        return redirect(url_for("settings_page"))

    return render_template_string(TPL["settings"])



# ---- Audit (Dom only) ----
@app.route("/audit")
@role_required("dom")
def audit_page():
    # --- Filters from query string ---
    qtext   = (request.args.get("q") or "").strip()
    action  = (request.args.get("action") or "").strip()
    target  = (request.args.get("target") or "").strip()
    user_id = (request.args.get("user_id") or "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    per_page = 50

    # --- Build query ---
    qry = Audit.query
    if action:
        qry = qry.filter(Audit.action == action)
    if target:
        qry = qry.filter(Audit.target == target)
    if user_id.isdigit():
        qry = qry.filter(Audit.actor_id == int(user_id))
    if qtext:
        like = f"%{qtext}%"
        qry = qry.filter(db.or_(Audit.details.ilike(like), Audit.target.ilike(like)))

    total = qry.count()
    items = (qry.order_by(Audit.created_at.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all())
    pages = (total + per_page - 1) // per_page

    # Distincts for filter dropdowns
    actions = [r[0] for r in db.session.query(Audit.action).distinct().all()]
    targets = [r[0] for r in db.session.query(Audit.target).distinct().all()]
    users   = User.query.order_by(User.name.asc()).all()

    return render_template_string(
        TPL["audit"],
        items=items, actions=sorted(actions), targets=sorted(t for t in targets if t),
        users=users, q=qtext, sel_action=action, sel_target=target, sel_user=user_id,
        page=page, pages=pages, total=total
    )



@app.route("/api/lock_status")
@login_required
def api_lock_status():
    lock = get_lock()
    remaining = None
    if lock.unlock_at:
        remaining = int((lock.unlock_at - datetime.now()).total_seconds())
        remaining = max(0, remaining)
    return jsonify({
        "locked": bool(lock.locked),
        "unlock_at": lock.unlock_at.isoformat() if lock.unlock_at else None,
        "unlock_at_fmt": fmt_dt(lock.unlock_at) if lock.unlock_at else "",
        "remaining": remaining
    })



# ---------- Templates (Tailwind dark UI) ----------
TPL = {
"signup": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Sign up (Dom)</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen flex items-center justify-center">
  <div class="w-full max-w-md p-6 rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 shadow-2xl">
    <h2 class="text-2xl font-bold mb-2 text-center">Create Dom Account</h2>
    <p class="text-sm text-zinc-400 mb-6 text-center">This must be done first. Then you’ll create the Sub.</p>
    <form method="post" class="space-y-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label class="block"><span class="text-sm text-zinc-300">Email</span>
        <input name="email" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="block"><span class="text-sm text-zinc-300">Display name</span>
        <input name="name" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="block"><span class="text-sm text-zinc-300">Password</span>
        <input type="password" name="password" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <button class="w-full rounded-xl bg-indigo-600 hover:bg-indigo-500 transition py-2.5 font-medium">Create & Sign in</button>
    </form>
    <p class="text-sm text-center mt-4 text-zinc-400">{{ get_flashed_messages() }}</p>
  </div>
</body></html>
""",

"login": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Login</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen flex items-center justify-center">
  <div class="w-full max-w-md p-6 rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 shadow-2xl">
    <h2 class="text-2xl font-bold mb-6 text-center">Sign in</h2>
    <form method="post" class="space-y-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label class="block"><span class="text-sm text-zinc-300">Email</span>
        <input name="email" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="block"><span class="text-sm text-zinc-300">Password</span>
        <input type="password" name="password" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="flex items-center gap-2 text-sm text-zinc-300">
        <input type="checkbox" name="remember" class="rounded bg-zinc-800 border-white/10"> Keep me signed in
    </label>
      <button class="w-full rounded-xl bg-indigo-600 hover:bg-indigo-500 transition py-2.5 font-medium">Login</button>
    </form>
    <p class="text-sm text-center mt-4 text-zinc-400">{{ get_flashed_messages() }}</p>
  </div>
</body></html>
""",

"dashboard": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <header class="sticky top-0 z-10 bg-zinc-950/80 backdrop-blur border-b border-white/10">
    <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
      <h2 class="text-xl font-semibold">Dashboard</h2>
      <nav class="flex gap-3 text-sm">
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('rules_page') }}">Rules</a>
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('profile_page') }}">Profile</a>
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('tasks_page') }}">Tasks</a>
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('punishments_page') }}">Punishments</a>
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('lock_page') }}">Lock</a>
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('journal_page') }}">Journal</a>
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('checkins') }}">Check-ins</a>
        {% if current_user.role=='dom' %}<a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('users_page') }}">Users</a>{% endif %}
        {% if current_user.role=='dom' %}<a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('audit_page') }}">Audit</a>{% endif %}
        <a class="px-3 py-1.5 rounded-lg hover:bg-white/10" href="{{ url_for('settings_page') }}">Settings</a>
      </nav>
    </div>
  </header>

  <main class="max-w-6xl mx-auto px-4 py-6 space-y-8">

    <!-- Top stats grid -->
    <section class="grid md:grid-cols-4 gap-6">
      <!-- Points -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-semibold">Points</h3>
          <a class="text-xs text-indigo-300 hover:underline" href="{{ url_for('leaderboard') }}">Leaderboard</a>
        </div>
        <div class="mt-3 text-3xl font-bold tabular-nums">{{ current_user.points_total }}</div>
        <div class="text-sm text-zinc-400">
          Weekly: <strong>{{ current_user.points_week }}</strong>
          {% if current_user.role=='sub' %} · Streak: <strong>{{ current_user.streak }}</strong> · Mult: <strong>{{ '%.2f'|format(current_user.multiplier or 1.0) }}×</strong>{% endif %}
        </div>
      </div>

      <!-- Lock -->
      <a href="{{ url_for('lock_page') }}" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5 block hover:bg-zinc-900 transition">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-semibold">Lock</h3>
          <span class="text-xs px-2 py-0.5 rounded-full {{ 'bg-rose-600/30 text-rose-300' if lock.locked else 'bg-emerald-600/30 text-emerald-300' }}">
            {{ 'LOCKED' if lock.locked else 'UNLOCKED' }}
          </span>
        </div>
        {% if lock.unlock_at %}
          <div class="text-sm text-zinc-400 mt-2">until {{ fmt_dt(lock.unlock_at) }}</div>
        {% endif %}
      </a>

    {% if sub_for_profile %}
      <a href="{% if current_user.role == 'sub' %}{{ url_for('profile_page') }}{% else %}{{ url_for('profile_page', uid=sub_for_profile.id) }}{% endif %}"
        class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5 block hover:bg-zinc-900 transition">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-semibold">Profile</h3>
          <span class="text-xs px-2 py-0.5 rounded-full bg-white/10 text-zinc-300">
            {{ sub_for_profile.name }}
          </span>
        </div>
        <div class="text-sm text-zinc-400 mt-2">
          Last orgasm:
          <strong>
            {% if prof and prof.last_orgasm_at %}{{ prof.last_orgasm_at|humandelta }}{% else %}—{% endif %}
          </strong>
          · Weight:
          <strong>
            {% if latest_weight %}{{ '%.1f'|format(latest_weight.value) }} kg
            {% elif prof and prof.weight_kg %}{{ '%.1f'|format(prof.weight_kg) }} kg
            {% else %}—{% endif %}
          </strong>
        </div>
      </a>
    {% else %}
      <div class="rounded-2xl bg-zinc-900/40 ring-1 ring-white/10 p-5 flex items-center">
        <div>
          <div class="text-lg font-semibold">Profile</div>
          <div class="text-sm text-zinc-400 mt-1">
            No sub linked yet.
            {% if current_user.role == 'dom' %}Create an invite to get started.{% endif %}
          </div>
        </div>
      </div>
    {% endif %}

      
      <!-- Tasks summary -->
      <a href="{{ url_for('tasks_page') }}" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5 block hover:bg-zinc-900 transition">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-semibold">Tasks</h3>
          <span class="text-xs px-2 py-0.5 rounded-full bg-blue-600/30 text-blue-300">{{ stats.tasks_active }} active</span>
        </div>
        <div class="text-sm text-zinc-400 mt-2">
          {% if current_user.role=='sub' %}
            Your open tasks
          {% else %}
            All open tasks
          {% endif %}
        </div>
      </a>
    </section>

      {# Show only to DOMs #}
  {% if current_user.role == 'dom' %}
  <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-3">
    <h3 class="font-semibold">Invite a sub</h3>
    <form method="post" action="{{ url_for('pair_invite_new') }}" class="flex flex-wrap gap-2 items-end">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label class="text-sm">
        <span>Max uses</span>
        <input type="number" name="max_uses" min="1" max="50" value="1"
              class="block mt-1 w-28 rounded bg-zinc-800/70 border border-white/10 px-2 py-1">
      </label>
      <label class="text-sm">
        <span>Expires in (hours)</span>
        <input type="number" name="expires_hours" min="0" placeholder="72"
              class="block mt-1 w-36 rounded bg-zinc-800/70 border border-white/10 px-2 py-1">
      </label>
      <button class="px-3 py-2 rounded bg-indigo-600 hover:bg-indigo-500">Create Invite</button>
    </form>
  </div>
  {% endif %}

    <!-- Second row -->
    <section class="grid md:grid-cols-3 gap-6">
      <!-- Punishments -->
      <a href="{{ url_for('punishments_page') }}" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5 block hover:bg-zinc-900 transition">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-semibold">Punishments</h3>
          <span class="text-xs px-2 py-0.5 rounded-full bg-rose-600/30 text-rose-300">{{ stats.punishments_pending }} pending</span>
        </div>
        <div class="text-sm text-zinc-400 mt-2">Queued items awaiting action</div>
      </a>

      <!-- Rules -->
      <a href="{{ url_for('rules_page') }}" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5 block hover:bg-zinc-900 transition">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-semibold">Rules</h3>
          <span class="text-xs px-2 py-0.5 rounded-full bg-white/10 text-zinc-300">{{ stats.rules_count }} total</span>
        </div>
        {% if stats.rules_ack_pending and current_user.role=='sub' %}
          <div class="text-sm text-amber-300 mt-2">{{ stats.rules_ack_pending }} need acknowledgement</div>
        {% else %}
          <div class="text-sm text-zinc-400 mt-2">Review and manage rules</div>
        {% endif %}
      </a>

      <!-- Check-ins -->
      <a href="{{ url_for('checkins') }}" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5 block hover:bg-zinc-900 transition">
        <div class="flex items-center justify-between">
          <h3 class="text-lg font-semibold">Check-ins</h3>
        </div>
        <div class="text-sm text-zinc-400 mt-2">
          Last: {% if last_checkin %}{{ fmt_dt(last_checkin.created_at) }}{% else %}—{% endif %}
        </div>
      </a>
    </section>

    <!-- Detailed lists (keep your original sections) -->
    <section class="grid md:grid-cols-2 gap-6">
      <!-- Active Rules -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
        <h3 class="text-lg font-semibold mb-3">Active Rules</h3>
        <ul class="space-y-2">
          {% for r in rules if r.active %}
            <li class="p-3 rounded-xl bg-zinc-800/50 border border-white/5">
              <div class="font-medium">{{ r.title }}</div>
              <div class="text-sm text-zinc-400">{{ r.description }}</div>
            </li>
          {% else %}
            <li class="text-zinc-400">No active rules.</li>
          {% endfor %}
        </ul>
      </div>

      <!-- Task list (role-aware) -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
        <h3 class="text-lg font-semibold mb-3">Your Tasks</h3>
        <ul class="space-y-2">
          {% for t in tasks %}
            <li class="p-3 rounded-xl bg-zinc-800/50 border border-white/5 flex items-center gap-3">
              <span class="text-xs px-2 py-0.5 rounded-full {{ 'bg-blue-600/30 text-blue-300' if t.status=='open' else 'bg-emerald-600/30 text-emerald-300' if t.status=='done' else 'bg-purple-600/30 text-purple-300' }}">{{ t.status }}</span>
              <div class="flex-1">
                <div class="font-medium">{{ t.title }}</div>
                <div class="text-xs text-zinc-400">
                  {% if t.due_at %}Due {{ fmt_dt(t.due_at) }} · {% endif %}Points {{ t.points }}
                </div>
              </div>
              {% if current_user.role=='sub' and t.status=='open' %}
                <form method="post" action="{{ url_for('task_complete', tid=t.id) }}">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                  <button class="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3 py-1.5 text-sm">Mark Done</button>
                </form>
              {% elif current_user.role=='dom' and t.status=='done' %}
                <a class="rounded-lg bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5 text-sm" href="{{ url_for('task_verify', tid=t.id) }}">Verify</a>
              {% endif %}
            </li>
          {% else %}
            <li class="text-zinc-400">No tasks.</li>
          {% endfor %}
        </ul>
      </div>
    </section>

<!-- Recent Activity (collapsible, hidden by default) -->
<section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
  <div class="flex items-center justify-between">
    <h3 class="text-lg font-semibold">Recent Activity</h3>
    <button id="audit-toggle"
            class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700"
            aria-controls="audit-content"
            aria-expanded="false">
      Show Activity
    </button>
  </div>

  <div id="audit-content" class="hidden mt-4 space-y-4">
    <!-- Filter/search bar -->
    <form method="get" action="{{ url_for('dashboard') }}" class="flex flex-wrap gap-2 text-sm">
      <select name="atype" class="rounded-lg bg-zinc-800/70 border border-white/10 px-2 py-1">
        {% set opts = [
          ('all','All'), ('auth','Auth'), ('invite','Invites'), ('journal','Journal'),
          ('task','Tasks'), ('punishment','Punishments'), ('rule','Rules'),
          ('checkin','Check-ins'), ('lock','Lock'), ('points','Points'), ('user','Users')
        ] %}
        {% for val,label in opts %}
          <option value="{{ val }}" {{ 'selected' if atype==val else '' }}>{{ label }}</option>
        {% endfor %}
      </select>
      <input name="q" value="{{ q or '' }}" placeholder="Search…"
             class="rounded-lg bg-zinc-800/70 border border-white/10 px-2 py-1" />
      <input type="hidden" name="limit" value="{{ limit }}">
      <button class="rounded-lg bg-zinc-700 hover:bg-zinc-600 px-3 py-1">Apply</button>
    </form>

    <!-- Feed -->
    <ul class="space-y-2">
      {% set current_day = None %}
      {% for a in history %}
        {% set day = a.created_at.date() %}
        {% if day != current_day %}
          <li class="pt-2 text-xs uppercase tracking-wider text-zinc-400">{{ day.strftime('%A, %b %d') }}</li>
          {% set current_day = day %}
        {% endif %}

        {% set m = a.action|audit_meta %}
        <li class="flex items-start gap-3 p-3 rounded-xl bg-zinc-800/40 ring-1 ring-white/10">
          <span class="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full ring-1 {{ m.cls }}">
            <span>{{ m.icon }}</span><span>{{ m.label }}</span>
          </span>
          <div class="flex-1">
            <div class="font-medium">{{ a.target }}</div>
            {% if a.details %}
              <div class="text-xs text-zinc-400 truncate">{{ a.details }}</div>
            {% endif %}
          </div>
          <span class="text-xs text-zinc-400 whitespace-nowrap">{{ fmt_dt(a.created_at) }}</span>
        </li>
      {% else %}
        <li class="text-zinc-400">No recent events.</li>
      {% endfor %}
    </ul>

    <div class="text-right">
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700"
         href="{{ url_for('dashboard', atype=atype, q=q, limit=limit+20) }}">
        Show more
      </a>
    </div>
  </div>

  <script>
    (function () {
      const KEY = "dashAuditCollapsed"; // '1' collapsed (default), '0' expanded
      const btn = document.getElementById("audit-toggle");
      const content = document.getElementById("audit-content");

      function applyState(collapsed) {
        if (collapsed) {
          content.classList.add("hidden");
          btn.setAttribute("aria-expanded", "false");
          btn.textContent = "Show Activity";
        } else {
          content.classList.remove("hidden");
          btn.setAttribute("aria-expanded", "true");
          btn.textContent = "Hide Activity";
        }
      }

      // default to collapsed if nothing stored
      const stored = localStorage.getItem(KEY);
      const collapsed = stored === null ? true : stored === "1";
      applyState(collapsed);

      btn.addEventListener("click", function (e) {
        e.preventDefault();
        const isHidden = content.classList.toggle("hidden");
        applyState(isHidden);
        localStorage.setItem(KEY, isHidden ? "1" : "0");
      });
    })();
  </script>
</section>



    {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}
    <div class="mt-4 space-y-2">
      {% for cat, m in msgs %}
        <div class="rounded-lg px-3 py-2 text-sm ring-1
                    {% if cat == 'error' %} bg-rose-900/40 ring-rose-700/40 text-rose-200
                    {% elif cat == 'success' %} bg-emerald-900/40 ring-emerald-700/40 text-emerald-200
                    {% else %} bg-zinc-900/70 ring-white/10 text-zinc-200 {% endif %}">
          {{ m }}
        </div>
      {% endfor %}
    </div>
  {% endif %}
{% endwith %}

  </main>
</body></html>
""",

"invite": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Invitation</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-md mx-auto px-4 py-8 space-y-4">
    <h1 class="text-xl font-semibold">You've been invited</h1>
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-2">
      <p>Join a private space.</p>
      <ul class="text-sm text-zinc-400">
        <li>Created by: <span class="text-zinc-200">{{ creator_label }}</span></li>
        <li>Uses: {{ invite.used_count }}/{{ invite.max_uses }}</li>
        <li>Expires: {{ invite.expires_at or 'no expiry' }}</li>
      </ul>

      {% if can_direct_accept %}
        <form method="post" action="{{ url_for('pair_invite_accept', code=invite.code) }}" class="mt-3">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <button class="w-full px-3 py-2 rounded bg-emerald-600 hover:bg-emerald-500">Accept as current account</button>
        </form>
      {% else %}
        <a href="{{ url_for('pair_invite_signup', code=invite.code) }}"
           class="block text-center w-full px-3 py-2 rounded bg-emerald-600 hover:bg-emerald-500 mt-3">
           Sign up as a sub to join
        </a>
        {% if current_user.is_authenticated %}
          <p class="text-xs text-zinc-400 mt-2">
            You're logged in as {{ current_user.email or 'this account' }}. If this isn't the account you want to bind,
            open this link in a private window or log out first.
          </p>
        {% endif %}
      {% endif %}
    </div>

    <a href="{{ url_for('login') }}" class="inline-block text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700">Back</a>
  </div>
</body></html>
""",

"invite_signup": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Sign up</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-md mx-auto px-4 py-8 space-y-4">
    <h1 class="text-xl font-semibold">Create your sub account</h1>
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-3">
      <form method="post" class="space-y-3">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        {% if supports_username %}
        <label class="block text-sm">
          <span>Username (optional)</span>
          <input name="username" class="mt-1 w-full rounded bg-zinc-800/70 border border-white/10 px-3 py-2">
        </label>
        {% endif %}
        {% if supports_display_name %}
        <label class="block text-sm">
          <span>Display name (optional)</span>
          <input name="display_name" class="mt-1 w-full rounded bg-zinc-800/70 border border-white/10 px-3 py-2">
        </label>
        {% endif %}
        <label class="block text-sm">
          <span>Email</span>
          <input name="email" type="email" required class="mt-1 w-full rounded bg-zinc-800/70 border border-white/10 px-3 py-2">
        </label>
        <label class="block text-sm">
          <span>Password</span>
          <input name="password" type="password" required class="mt-1 w-full rounded bg-zinc-800/70 border border-white/10 px-3 py-2">
        </label>
        <button class="w-full rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-2">Create account & join</button>
      </form>
      <p class="text-xs text-zinc-400">Invite from: {{ creator_label }}</p>
    </div>
    <a href="{{ url_for('pair_invite_view', code=invite.code) }}" class="inline-block text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700">Back</a>
  </div>
</body></html>
""",


"profile": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Profile</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-4xl mx-auto px-4 py-6 space-y-6">

    <!-- Header with Dom sub-switcher -->
    <div class="flex items-center justify-between gap-3 flex-wrap">
      <h2 class="text-xl font-semibold">
        Profile — {{ sub.name }} <span class="text-zinc-400 text-sm">({{ sub.email }})</span>
      </h2>
      <div class="flex items-center gap-2">
        {% if current_user.role == 'dom' and subs and subs|length > 1 %}
          <form method="get" action="{{ url_for('profile_page') }}" class="text-sm">
            <label class="sr-only" for="subswitch">Switch sub</label>
            <select id="subswitch" name="uid"
                    class="rounded-lg bg-zinc-800/70 border border-white/10 px-2 py-1"
                    onchange="this.form.submit()">
              {% for s in subs %}
                <option value="{{ s.id }}" {{ 'selected' if s.id == sub.id else '' }}>{{ s.name }}</option>
              {% endfor %}
            </select>
            <noscript><button class="px-2 py-1 rounded bg-zinc-700">Go</button></noscript>
          </form>
        {% endif %}
        <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
      </div>
    </div>

    <!-- Row 1: Days + 3 orgasm counters -->
    <section class="grid md:grid-cols-4 gap-6">
      <!-- Days since last orgasm -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="flex items-center justify-between">
          <div class="text-sm text-zinc-400">Days since last orgasm</div>
          <span class="text-xs px-2 py-0.5 rounded-full
            {% if prof.orgasm_policy=='denied' %} bg-rose-600/30 text-rose-300
            {% elif prof.orgasm_policy in ['edging','ruined'] %} bg-amber-600/30 text-amber-300
            {% else %} bg-emerald-600/30 text-emerald-300 {% endif %}">
            {{ (prof.orgasm_policy or 'allowed')|capitalize }}
          </span>
        </div>
        <div class="mt-2 text-4xl font-bold tabular-nums">
          {{ days_since if days_since is not none else '—' }}
        </div>
        <div class="text-xs text-zinc-500 mt-1">
          Last: {{ prof.last_orgasm_at|humandelta if prof.last_orgasm_at else '—' }}
        </div>
      </div>

      <!-- Orgasms Today -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="text-sm text-zinc-400">Orgasms — Today</div>
        <div class="mt-2 text-4xl font-bold tabular-nums">{{ orgasms_today }}</div>
        <div class="text-xs text-zinc-500 mt-1">UTC day</div>
      </div>

      <!-- Orgasms This Week -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="text-sm text-zinc-400">Orgasms — This Week</div>
        <div class="mt-2 text-4xl font-bold tabular-nums">{{ orgasms_week }}</div>
        <div class="text-xs text-zinc-500 mt-1">Week starts Monday (UTC)</div>
      </div>

      <!-- Orgasms This Month -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="text-sm text-zinc-400">Orgasms — This Month</div>
        <div class="mt-2 text-4xl font-bold tabular-nums">{{ orgasms_month }}</div>
        <div class="text-xs text-zinc-500 mt-1">Month boundaries in UTC</div>
      </div>
    </section>

    <!-- Row 2: Weight + Waist -->
    <section class="grid md:grid-cols-2 gap-6">
      <!-- Weight -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="flex items-center justify-between">
          <div class="text-sm text-zinc-400">Weight</div>
          {% set d = weight_summary.delta %}
          <div class="text-xs">
            {% if d is not none %}
              {% if d > 0 %}<span class="text-rose-300">▲ {{ '%.1f'|format(d) }} {{ weight_summary.unit }}</span>
              {% elif d < 0 %}<span class="text-emerald-300">▼ {{ '%.1f'|format(-d) }} {{ weight_summary.unit }}</span>
              {% else %}<span class="text-zinc-400">—</span>{% endif %}
            {% else %}
              <span class="text-zinc-400">—</span>
            {% endif %}
          </div>
        </div>
        <div class="mt-1 text-2xl font-semibold">
          {% if weight_summary.latest %}{{ '%.1f'|format(weight_summary.latest.value) }} {{ weight_summary.unit }}{% else %}—{% endif %}
        </div>
        {% if weight_summary.points %}
          <svg width="{{ weight_summary.svg_w }}" height="{{ weight_summary.svg_h }}" class="mt-2 block">
            <polyline fill="none" stroke="currentColor" stroke-width="2" class="text-zinc-400/70"
                      points="{{ weight_summary.points }}" />
          </svg>
        {% endif %}
        <div class="text-xs text-zinc-500 mt-1">
          {% if weight_summary.latest %}Logged {{ fmt_dt(weight_summary.latest.created_at) }}{% else %}No entries yet{% endif %}
        </div>
      </div>

      <!-- Waist -->
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="flex items-center justify-between">
          <div class="text-sm text-zinc-400">Waist</div>
          {% set d = waist_summary.delta %}
          <div class="text-xs">
            {% if d is not none %}
              {% if d > 0 %}<span class="text-rose-300">▲ {{ '%.1f'|format(d) }} {{ waist_summary.unit }}</span>
              {% elif d < 0 %}<span class="text-emerald-300">▼ {{ '%.1f'|format(-d) }} {{ waist_summary.unit }}</span>
              {% else %}<span class="text-zinc-400">—</span>{% endif %}
            {% else %}
              <span class="text-zinc-400">—</span>
            {% endif %}
          </div>
        </div>
        <div class="mt-1 text-2xl font-semibold">
          {% if waist_summary.latest %}{{ '%.1f'|format(waist_summary.latest.value) }} {{ waist_summary.unit }}{% else %}—{% endif %}
        </div>
        {% if waist_summary.points %}
          <svg width="{{ waist_summary.svg_w }}" height="{{ waist_summary.svg_h }}" class="mt-2 block">
            <polyline fill="none" stroke="currentColor" stroke-width="2" class="text-zinc-400/70"
                      points="{{ waist_summary.points }}" />
          </svg>
        {% endif %}
        <div class="text-xs text-zinc-500 mt-1">
          {% if waist_summary.latest %}Logged {{ fmt_dt(waist_summary.latest.created_at) }}{% else %}No entries yet{% endif %}
        </div>
      </div>
    </section>

    <!-- Manage (Sub-only) -->
    <section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-3">
      <h3 class="font-semibold">Manage</h3>

      {% if current_user.role == 'sub' and current_user.id == sub.id %}
      <form method="post" class="space-y-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <!-- Policy radio pills -->
        <div class="text-sm">
          <div class="text-zinc-400 mb-1">Orgasm policy</div>
          <div class="flex flex-wrap gap-2">
            {% for opt in ['allowed','denied','edging','ruined','custom'] %}
              <label class="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl ring-1 ring-white/10 cursor-pointer
                {% if prof.orgasm_policy==opt %} bg-white/10 {% else %} bg-zinc-800/50 hover:bg-zinc-800 {% endif %}">
                <input class="sr-only" type="radio" name="orgasm_policy" value="{{ opt }}" {% if prof.orgasm_policy==opt %}checked{% endif %}>
                <span class="capitalize">{{ opt }}</span>
              </label>
            {% endfor %}
          </div>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <label class="block text-sm">
            <span>Weight (kg)</span>
            <input name="weight_kg" value="{{ prof.weight_kg or '' }}" placeholder="e.g. 62.4"
                   class="mt-1 w-full rounded bg-zinc-800/70 border border-white/10 px-3 py-2">
          </label>
          <label class="block text-sm">
            <span>Waist (cm)</span>
            <input name="waist_cm" value="{{ prof.waist_cm or '' }}" placeholder="e.g. 70.0"
                   class="mt-1 w-full rounded bg-zinc-800/70 border border-white/10 px-3 py-2">
          </label>
        </div>

        <label class="block text-sm">
          <span>Notes</span>
          <textarea name="notes" rows="3" placeholder="Anything you want your dom to see…"
                    class="mt-1 w-full rounded bg-zinc-800/70 border border-white/10 px-3 py-2">{{ prof.notes or '' }}</textarea>
        </label>

        <div class="flex flex-wrap gap-2">
          <button type="submit" name="action" value="save_profile"
                  class="rounded bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Save Profile</button>
          <button type="submit" name="action" value="log_orgasm" formnovalidate
                  class="rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-2 text-sm">Log Orgasm</button>
          <button type="submit" name="action" value="log_denial" formnovalidate
                  class="rounded bg-rose-600 hover:bg-rose-500 px-3 py-2 text-sm">Log Denial</button>
        </div>
      </form>
      {% else %}
        <p class="text-sm text-zinc-400">View-only. The sub controls their own profile.</p>
      {% endif %}
    </section>

    <!-- Row 3: Logs -->
    <section class="grid md:grid-cols-2 gap-6">
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <h3 class="font-semibold mb-3">Orgasm & Denial Log</h3>
        <ul class="space-y-2 text-sm">
          {% for e in events %}
            <li class="flex items-center justify-between p-2 rounded bg-zinc-800/40 ring-1 ring-white/10">
              <span class="capitalize">{{ e.kind }}</span>
              <span class="text-zinc-400">{{ fmt_dt(e.created_at) }}</span>
            </li>
          {% else %}
            <li class="text-zinc-400">No events yet.</li>
          {% endfor %}
        </ul>
      </div>

      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <h3 class="font-semibold mb-3">Body Metrics</h3>
        <ul class="space-y-2 text-sm">
          {% for m in metrics %}
            <li class="flex items-center justify-between p-2 rounded bg-zinc-800/40 ring-1 ring-white/10">
              <span class="capitalize">{{ m.kind }} — {{ '%.2f'|format(m.value) }} {{ m.unit }}</span>
              <span class="text-zinc-400">{{ fmt_dt(m.created_at) }}</span>
            </li>
          {% else %}
            <li class="text-zinc-400">No metrics yet.</li>
          {% endfor %}
        </ul>
      </div>
    </section>

    <!-- Flashes -->
    {% with msgs = get_flashed_messages(with_categories=true) %}
      {% if msgs %}
        <div class="space-y-2">
          {% for cat, m in msgs %}
            <div class="rounded-lg px-3 py-2 text-sm ring-1
              {% if cat == 'error' %} bg-rose-900/40 ring-rose-700/40 text-rose-200
              {% elif cat == 'success' %} bg-emerald-900/40 ring-emerald-700/40 text-emerald-200
              {% else %} bg-zinc-900/70 ring-white/10 text-zinc-200 {% endif %}">
              {{ m }}
            </div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
  </div>
</body></html>
""",





"rules": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Rules</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Rules</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>

    <!-- Filters / Actions -->
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 flex flex-wrap items-center gap-3">
      <div class="text-sm">
        View:
        <a class="px-2 py-1 rounded {{ 'bg-white/10' if view=='active' else 'hover:bg-white/10' }}" href="{{ url_for('rules_page', view='active', cat=category) }}">Active</a>
        <a class="px-2 py-1 rounded {{ 'bg-white/10' if view=='all' else 'hover:bg-white/10' }}" href="{{ url_for('rules_page', view='all', cat=category) }}">All</a>
      </div>
      <div class="text-sm">
        Category:
        <a class="px-2 py-1 rounded {{ 'bg-white/10' if not category else 'hover:bg-white/10' }}" href="{{ url_for('rules_page', view=view) }}">Any</a>
        {% for c in cats %}
          <a class="px-2 py-1 rounded {{ 'bg-white/10' if category==c else 'hover:bg-white/10' }}" href="{{ url_for('rules_page', view=view, cat=c) }}">{{ c }}</a>
        {% endfor %}
      </div>

      {% if current_user.role=='sub' %}
      <form method="post" class="ml-auto">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="ack_all">
        <button class="text-sm px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500">Acknowledge All</button>
      </form>
      {% endif %}
    </div>

    {% if current_user.role=='dom' %}
    <!-- Create Rule -->
    <form method="post" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 grid md:grid-cols-3 gap-3">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <input type="hidden" name="action" value="create">
      <label class="md:col-span-1"><span class="text-sm text-zinc-300">Title</span>
        <input name="title" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="md:col-span-2"><span class="text-sm text-zinc-300">Description</span>
        <input name="description" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label><span class="text-sm text-zinc-300">Category</span>
        <input name="category" placeholder="general" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label><span class="text-sm text-zinc-300">Severity (1–5)</span>
        <input name="severity" type="number" min="1" max="5" value="2" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label><span class="text-sm text-zinc-300">Penalty points</span>
        <input name="penalty_points" type="number" value="0" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="flex items-center gap-2 text-sm text-zinc-300">
        <input type="checkbox" name="requires_ack" checked class="rounded bg-zinc-800 border-white/10"> Requires acknowledgement
      </label>
      <label><span class="text-sm text-zinc-300">Active from (YYYY-MM-DD HH:MM)</span>
        <input name="active_from" placeholder="" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label><span class="text-sm text-zinc-300">Active until (YYYY-MM-DD HH:MM)</span>
        <input name="active_until" placeholder="" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <div class="md:col-span-3">
        <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Add Rule</button>
      </div>
    </form>
    {% endif %}

    <!-- List -->
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-zinc-900/90">
          <tr class="text-left">
            <th class="px-4 py-3">#</th>
            <th class="px-4 py-3">Title</th>
            <th class="px-4 py-3">Category</th>
            <th class="px-4 py-3">Severity</th>
            <th class="px-4 py-3">Penalty</th>
            <th class="px-4 py-3">Status</th>
            <th class="px-4 py-3">Window</th>
            <th class="px-4 py-3">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-white/5">
          {% for r in rules %}
          <tr class="align-top hover:bg-white/5">
            <td class="px-4 py-3">{{ r.sort_order }}</td>
            <td class="px-4 py-3">
              <div class="font-medium">{{ r.title }}</div>
              <div class="text-xs text-zinc-400">{{ r.description }}</div>
              {% if current_user.role=='sub' and r.requires_ack %}
                <div class="text-xs mt-1">
                  {% if r.id in acked_ids %}
                    <span class="px-2 py-0.5 rounded bg-emerald-600/30 text-emerald-300">acknowledged</span>
                  {% else %}
                    <span class="px-2 py-0.5 rounded bg-amber-600/30 text-amber-300">awaiting ack</span>
                  {% endif %}
                </div>
              {% endif %}
            </td>
            <td class="px-4 py-3">{{ r.category }}</td>
            <td class="px-4 py-3">{{ r.severity }}</td>
            <td class="px-4 py-3">{{ r.penalty_points }}</td>
            <td class="px-4 py-3">
              <span class="text-xs px-2 py-0.5 rounded-full {{ 'bg-emerald-600/30 text-emerald-300' if r.active else 'bg-zinc-700 text-zinc-300' }}">{{ 'ACTIVE' if r.active else 'OFF' }}</span>
              {% if r.requires_ack %}<span class="ml-1 text-xs px-2 py-0.5 rounded-full bg-indigo-600/30 text-indigo-300">req. ack</span>{% endif %}
            </td>
            <td class="px-4 py-3 text-xs text-zinc-400">
              {% if r.active_from %}from {{ fmt_dt(r.active_from) }}{% endif %}
              {% if r.active_until %}{% if r.active_from %} · {% endif %}until {{ fmt_dt(r.active_until) }}{% endif %}
            </td>
            <td class="px-4 py-3">
              {% if current_user.role=='dom' %}
              <div class="flex flex-wrap items-center gap-2">
                <!-- Toggle -->
                <a class="px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('rule_toggle', rid=r.id) }}">{{ 'Disable' if r.active else 'Enable' }}</a>

                <!-- Reorder -->
                <form method="post" action="{{ url_for('rule_reorder', rid=r.id, direction='up') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700">↑</button></form>
                <form method="post" action="{{ url_for('rule_reorder', rid=r.id, direction='down') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700">↓</button></form>

                <!-- Inline edit (POST update) -->
                <details class="w-full">
                  <summary class="cursor-pointer text-zinc-300">Edit</summary>
                  <form method="post" class="mt-2 grid md:grid-cols-3 gap-2">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="id" value="{{ r.id }}">
                    <input name="title" value="{{ r.title }}" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1 md:col-span-1"/>
                    <input name="description" value="{{ r.description }}" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1 md:col-span-2"/>
                    <input name="category" value="{{ r.category }}" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1"/>
                    <input name="severity" type="number" min="1" max="5" value="{{ r.severity }}" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1"/>
                    <input name="penalty_points" type="number" value="{{ r.penalty_points }}" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1"/>
                    <label class="flex items-center gap-2 text-xs text-zinc-300">
                      <input type="checkbox" name="requires_ack" {{ 'checked' if r.requires_ack else '' }} class="rounded bg-zinc-800 border-white/10"> requires ack
                    </label>
                    <input name="active_from" value="{{ r.active_from.isoformat(sep=' ', timespec='minutes') if r.active_from else '' }}" placeholder="YYYY-MM-DD HH:MM" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1"/>
                    <input name="active_until" value="{{ r.active_until.isoformat(sep=' ', timespec='minutes') if r.active_until else '' }}" placeholder="YYYY-MM-DD HH:MM" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1"/>
                    <button class="rounded bg-indigo-600 hover:bg-indigo-500 px-3 py-1">Save</button>
                  </form>
                </details>

                <!-- Delete -->
                <form method="post" action="{{ url_for('rule_delete', rid=r.id) }}" onsubmit="return confirm('Delete rule?')">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                  <button class="px-2 py-1 rounded bg-rose-600 hover:bg-rose-500">Delete</button>
                </form>
              </div>
              {% endif %}
            </td>
          </tr>
          {% else %}
          <tr><td colspan="8" class="px-4 py-6 text-zinc-400">No rules yet.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <p class="text-sm text-zinc-400 mt-2">{{ get_flashed_messages() }}</p>
  </div>
</body></html>
""",


"leaderboard":  """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Leaderboard</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-3xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Weekly Leaderboard</h2>
      <div class="flex gap-2">
        <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
        {% if current_user.role=='dom' %}
        <form method="post" action="{{ url_for('close_week') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <button class="text-sm px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500">Close Week</button>
        </form>
        {% endif %}
      </div>
    </div>

    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-zinc-900/90">
          <tr class="text-left">
            <th class="px-4 py-3">User</th>
            <th class="px-4 py-3">Weekly</th>
            <th class="px-4 py-3">Total</th>
            <th class="px-4 py-3">Streak</th>
            <th class="px-4 py-3">Mult</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-white/5">
          {% for u in users %}
          <tr class="hover:bg-white/5">
            <td class="px-4 py-3">{{ u.name }}</td>
            <td class="px-4 py-3">{{ u.points_week }}</td>
            <td class="px-4 py-3">{{ u.points_total }}</td>
            <td class="px-4 py-3">{{ u.streak }}</td>
            <td class="px-4 py-3">{{ "%.0f%%"|format((u.multiplier or 1.0) * 100) }}</td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="px-4 py-6 text-zinc-400">No data.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <p class="text-sm text-zinc-400">{{ get_flashed_messages() }}</p>
  </div>
</body></html>
""",




"tasks": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Tasks</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Tasks</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>

    {% if current_user.role=='dom' %}
    <form method="post" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 grid md:grid-cols-2 gap-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label><span class="text-sm text-zinc-300">Title</span>
        <input name="title" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label><span class="text-sm text-zinc-300">Points</span>
        <input name="points" type="number" value="0" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="md:col-span-2"><span class="text-sm text-zinc-300">Description</span>
        <textarea name="description" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"></textarea>
      </label>
      <label class="md:col-span-2"><span class="text-sm text-zinc-300">Due (YYYY-MM-DD HH:MM)</span>
        <input name="due_at" placeholder="2025-08-17 20:00" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <div class="md:col-span-2">
        <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Create</button>
      </div>
    </form>
    {% endif %}

    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-zinc-900/90">
          <tr class="text-left">
            <th class="px-4 py-3">Status</th>
            <th class="px-4 py-3">Title</th>
            <th class="px-4 py-3">Due</th>
            <th class="px-4 py-3">Points</th>
            <th class="px-4 py-3">Action</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-white/5">
          {% for t in tasks %}
          <tr class="hover:bg-white/5">
            <td class="px-4 py-3">
              <span class="text-xs px-2 py-0.5 rounded-full {{ 'bg-blue-600/30 text-blue-300' if t.status=='open' else 'bg-emerald-600/30 text-emerald-300' if t.status=='done' else 'bg-purple-600/30 text-purple-300' }}">{{ t.status }}</span>
            </td>
            <td class="px-4 py-3 font-medium">{{ t.title }}</td>
            <td class="px-4 py-3">{{ t.due_at or '' }}</td>
            <td class="px-4 py-3">{{ t.points }}</td>
            <td class="px-4 py-3">
              {% if current_user.role=='sub' and t.status=='open' %}
              <form method="post" action="{{ url_for('task_complete', tid=t.id) }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3 py-1.5">Done</button>
              </form>
              {% elif current_user.role=='dom' and t.status=='done' %}
              <a class="rounded-lg bg-indigo-600 hover:bg-indigo-500 px-3 py-1.5" href="{{ url_for('task_verify', tid=t.id) }}">Verify</a>
              {% endif %}
            </td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="px-4 py-6 text-zinc-400">No tasks.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <p class="text-sm text-zinc-400">{{ get_flashed_messages() }}</p>
  </div>
</body></html>
""",

"punishments": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Punishments</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Punishments</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>

    <!-- Stats -->
    <div class="grid md:grid-cols-4 gap-3">
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="text-xs text-zinc-400">Total</div>
        <div class="text-2xl font-semibold">{{ total }}</div>
      </div>
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="text-xs text-zinc-400">Pending</div>
        <div class="text-2xl font-semibold">{{ pending }}</div>
      </div>
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="text-xs text-zinc-400">Completed</div>
        <div class="text-2xl font-semibold">{{ completed }}</div>
      </div>
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="text-xs text-zinc-400">Avg completion</div>
        <div class="text-2xl font-semibold">{{ '%.1f h'|format(avg_time) if avg_time else '—' }}</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 flex flex-wrap items-center gap-3">
      <div class="text-sm">
        View:
        <a class="px-2 py-1 rounded {{ 'bg-white/10' if view=='pending' else 'hover:bg-white/10' }}" href="{{ url_for('punishments_page', view='pending', cat=cat, status=status_filter) }}">Pending</a>
        <a class="px-2 py-1 rounded {{ 'bg-white/10' if view=='all' else 'hover:bg-white/10' }}" href="{{ url_for('punishments_page', view='all', cat=cat, status=status_filter) }}">All</a>
        {% if current_user.role=='sub' %}
        <a class="px-2 py-1 rounded {{ 'bg-white/10' if view=='mine' else 'hover:bg-white/10' }}" href="{{ url_for('punishments_page', view='mine', cat=cat, status=status_filter) }}">Mine</a>
        {% endif %}
      </div>
      <div class="text-sm">
        Category:
        <a class="px-2 py-1 rounded {{ 'bg-white/10' if not cat else 'hover:bg-white/10' }}" href="{{ url_for('punishments_page', view=view, status=status_filter) }}">Any</a>
        {% for c in cats %}
          <a class="px-2 py-1 rounded {{ 'bg-white/10' if cat==c else 'hover:bg-white/10' }}" href="{{ url_for('punishments_page', view=view, cat=c, status=status_filter) }}">{{ c }}</a>
        {% endfor %}
      </div>
      <div class="text-sm ml-auto flex items-center gap-2">
        <span>Status:</span>
        <select onchange="location.href='{{ url_for('punishments_page') }}?view={{ view }}&cat={{ cat }}&status='+this.value"
                class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1">
          {% for s in ['', 'queued','assigned','in_progress','completed','waived'] %}
            <option value="{{ s }}" {{ 'selected' if (status_filter==s) else '' }}>{{ s or 'Any' }}</option>
          {% endfor %}
        </select>
      </div>
    </div>

    {% if current_user.role=='dom' %}
    <!-- Queue new (no points) -->
    <form method="post" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 grid md:grid-cols-3 gap-3">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <input type="hidden" name="action" value="create">
      <label class="md:col-span-1"><span class="text-sm text-zinc-300">Title</span>
        <input name="title" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="md:col-span-2"><span class="text-sm text-zinc-300">Description</span>
        <input name="description" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label><span class="text-sm text-zinc-300">Category</span>
        <input name="category" placeholder="general" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label><span class="text-sm text-zinc-300">Severity (1–5)</span>
        <input name="severity" type="number" min="1" max="5" value="2" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <div class="md:col-span-3">
        <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Queue</button>
      </div>
    </form>
    {% endif %}

    <!-- List -->
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-zinc-900/90">
          <tr class="text-left">
            <th class="px-4 py-3">Title</th>
            <th class="px-4 py-3">Severity</th>
            <th class="px-4 py-3">Category</th>
            <th class="px-4 py-3">Status</th>
            <th class="px-4 py-3">Assigned</th>
            <th class="px-4 py-3">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-white/5">
          {% for p in items %}
          {% set sev_class = 'bg-emerald-600/30 text-emerald-300' if p.severity<=2 else ('bg-amber-600/30 text-amber-300' if p.severity==3 else 'bg-rose-600/30 text-rose-300') %}
          {% set row_tint = 'bg-white/0' if p.severity<=2 else ('bg-amber-500/5' if p.severity==3 else 'bg-rose-500/5') %}
          <tr class="align-top hover:bg-white/5 {{ row_tint }}">
            <td class="px-4 py-3">
              <div class="font-medium">{{ p.title }}</div>
              <div class="text-xs text-zinc-400">{{ p.description }}</div>
              {% if p.evidence_note or p.evidence_url %}
                <div class="text-xs text-zinc-400 mt-1">
                  <span class="text-zinc-300">Evidence:</span>
                  {{ p.evidence_note }}
                  {% if p.evidence_url %}<a class="text-indigo-300 hover:underline" href="{{ p.evidence_url }}" target="_blank">link</a>{% endif %}
                </div>
              {% endif %}
              <div class="text-[11px] text-zinc-500 mt-1">updated {{ fmt_dt(p.updated_at) }}</div>
            </td>

            <td class="px-4 py-3">
              <span class="text-xs px-2 py-0.5 rounded-full {{ sev_class }}">S{{ p.severity }}</span>
            </td>

            <td class="px-4 py-3">{{ p.category }}</td>

            <td class="px-4 py-3">
              <span class="text-xs px-2 py-0.5 rounded-full {{
                'bg-blue-600/30 text-blue-300' if p.status in ['queued','assigned'] else
                'bg-purple-600/30 text-purple-300' if p.status=='in_progress' else
                'bg-emerald-600/30 text-emerald-300' if p.status=='completed' else
                'bg-zinc-700 text-zinc-300'
              }}">{{ p.status.replace('_',' ') }}</span>
              {% if p.acknowledged %}
                <span class="ml-1 text-xs px-2 py-0.5 rounded-full bg-white/10 text-zinc-300">ack</span>
              {% endif %}
            </td>

            <td class="px-4 py-3">{{ p.assigned_to or '—' }}</td>

            <td class="px-4 py-3">
              <div class="flex flex-col gap-2">
                {% if current_user.role=='sub' %}
                  {% if not p.acknowledged and p.status in ['assigned','queued'] %}
                  <form method="post" class="inline">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="action" value="ack">
                    <input type="hidden" name="pid" value="{{ p.id }}">
                    <button class="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 w-full md:w-auto">Acknowledge</button>
                  </form>
                  {% endif %}

                  {% if p.status in ['assigned','in_progress'] %}
                  <form method="post" class="grid md:grid-cols-3 gap-2">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="action" value="complete">
                    <input type="hidden" name="pid" value="{{ p.id }}">
                    <input name="evidence_note" placeholder="What did you do?" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1 md:col-span-2"/>
                    <input name="evidence_url" placeholder="Optional link" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1"/>
                    <button class="rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-1 md:col-span-3">Mark Completed</button>
                  </form>
                  {% endif %}
                {% else %}
                  <form method="post" class="flex items-center gap-2">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="action" value="status">
                    <input type="hidden" name="pid" value="{{ p.id }}">
                    <select name="state" class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1">
                      {% for s in ['queued','assigned','in_progress','completed','waived'] %}
                        <option value="{{ s }}" {{ 'selected' if p.status==s else '' }}>{{ s.replace('_',' ') }}</option>
                      {% endfor %}
                    </select>
                    <button class="rounded bg-indigo-600 hover:bg-indigo-500 px-3 py-1">Update</button>
                    <button formaction="{{ url_for('punishments_page') }}" formmethod="post"
                            name="action" value="escalate"
                            class="rounded bg-rose-600 hover:bg-rose-500 px-3 py-1"
                            onclick="this.form.action='{{ url_for('punishments_page') }}';">
                      Escalate
                    </button>
                    <input type="hidden" name="pid" value="{{ p.id }}">
                  </form>
                {% endif %}
              </div>
            </td>
          </tr>
          {% else %}
          <tr><td colspan="6" class="px-4 py-6 text-zinc-400">None.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <p class="text-sm text-zinc-400">{{ get_flashed_messages() }}</p>
  </div>
</body></html>
""",



"lock": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Chastity Lock</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-3xl mx-auto px-4 py-6 space-y-6">

    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Chastity Control</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>

    <!-- Status Card -->
    <section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
      <div class="flex items-start justify-between gap-4">
        <div>
          <div class="text-sm text-zinc-400 mb-1">Current State</div>
          <div class="flex items-center gap-3">
            <span id="statePill" class="text-xs px-2 py-0.5 rounded-full {{ 'bg-rose-600/30 text-rose-300' if lock.locked else 'bg-emerald-600/30 text-emerald-300' }}">
              {{ 'LOCKED' if lock.locked else 'UNLOCKED' }}
            </span>
            <span id="untilTxt" class="text-xs text-zinc-400">
              {% if lock.unlock_at %}until {{ fmt_dt(lock.unlock_at) }}{% endif %}
            </span>
          </div>
        </div>
        <div class="text-right">
          <div class="text-sm text-zinc-400">Time Remaining</div>
          <div id="countdown" class="text-3xl font-bold tabular-nums">--:--:--</div>
        </div>
      </div>

      <div class="w-full h-2 bg-white/5 rounded-lg mt-4 overflow-hidden">
        <div id="progress" class="h-2 bg-indigo-500/70" style="width:0%"></div>
      </div>
    </section>

    {% if current_user.role=='dom' %}
    <!-- Dom Controls -->
    <section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5 space-y-5">
      <h3 class="text-lg font-semibold">Controls</h3>

      <!-- Quick presets -->
      <form method="post" class="flex flex-wrap gap-2">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="lock_quick">
        <button name="quick_minutes" value="60"  class="rounded-xl bg-zinc-800 hover:bg-zinc-700 px-3 py-2 text-sm">Lock +1h</button>
        <button name="quick_minutes" value="360" class="rounded-xl bg-zinc-800 hover:bg-zinc-700 px-3 py-2 text-sm">Lock +6h</button>
        <button name="quick_minutes" value="1440" class="rounded-xl bg-zinc-800 hover:bg-zinc-700 px-3 py-2 text-sm">Lock +24h</button>
        <button name="quick_minutes" value="4320" class="rounded-xl bg-zinc-800 hover:bg-zinc-700 px-3 py-2 text-sm">Lock +3d</button>
      </form>

      <!-- Add / Set exact -->
      <form method="post" class="grid md:grid-cols-3 gap-3 items-end">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label class="md:col-span-2">
          <span class="text-sm text-zinc-300">Set unlock (local time)</span>
          <input name="unlock_at"
                 type="text"
                 placeholder="{{ fmt_date(now_dt) }} {{ fmt_time(now_dt) }}"
                 class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <button name="action" value="lock_set" class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Set Until</button>

        <label>
          <span class="text-sm text-zinc-300">Add minutes</span>
          <input type="number" name="add_minutes" value="30" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <button name="action" value="add_time" class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Add Time</button>

        <label>
          <span class="text-sm text-zinc-300">Emergency PIN (optional)</span>
          <input name="emergency_pin" placeholder="set/overwrite" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
      </form>

      <form method="post" class="flex gap-3">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button name="action" value="lock" class="rounded-xl bg-rose-600 hover:bg-rose-500 px-4 py-2">Lock (no end)</button>
        <button name="action" value="unlock" class="rounded-xl bg-emerald-600 hover:bg-emerald-500 px-4 py-2">Unlock Now</button>
      </form>
    </section>
    {% else %}
    <!-- Sub request -->
    <section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
      <h3 class="text-lg font-semibold mb-3">Request Early Release</h3>
      <form method="post" class="grid md:grid-cols-3 gap-3">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label class="md:col-span-2"><span class="text-sm text-zinc-300">Reason / Note</span>
          <input name="note" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2" placeholder="Why request release?"/>
        </label>
        <div class="md:col-span-1 flex items-end">
          <button name="request_release" value="1" class="w-full rounded-xl bg-amber-600 hover:bg-amber-500 px-4 py-2">Send Request</button>
        </div>
      </form>
    </section>
    {% endif %}

    <!-- Recent History -->
    <section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
      <h3 class="text-lg font-semibold mb-3">Recent Activity</h3>
      <ul class="space-y-2 text-sm">
        {% for a in history %}
          <li class="flex items-center justify-between">
            <span class="text-zinc-300">{{ a.action|upper }}</span>
            <span class="text-zinc-400">{{ fmt_dt(a.created_at) }}</span>
          </li>
        {% else %}
          <li class="text-zinc-400">No recent events.</li>
        {% endfor %}
      </ul>
    </section>

    <p class="text-sm text-zinc-400">{{ get_flashed_messages() }}</p>
  </div>

  <!-- Live countdown -->
  <script>
    const pill = document.getElementById('statePill');
    const cd  = document.getElementById('countdown');
    const bar = document.getElementById('progress');
    const untilSpan = document.getElementById('untilTxt');

    let remaining = {{ remaining if remaining is not none else 'null' }};
    let total = remaining;

    function fmt(s){
      if(s == null) return "--:--:--";
      s = Math.max(0, s|0);
      const h = String(Math.floor(s/3600)).padStart(2,'0');
      const m = String(Math.floor((s%3600)/60)).padStart(2,'0');
      const sec = String(s%60).padStart(2,'0');
      return h+":"+m+":"+sec;
    }

    function tick(){
      if(remaining != null){
        remaining = Math.max(0, remaining-1);
        cd.textContent = fmt(remaining);
        if(total && total>0){
          const pct = Math.max(0, Math.min(100, 100 - (remaining/total*100)));
          bar.style.width = pct + '%';
        }
      } else {
        cd.textContent = "--:--:--";
        bar.style.width = '0%';
      }
    }

    async function refresh(){
      try{
        const r = await fetch("{{ url_for('api_lock_status') }}");
        const j = await r.json();
        const wasNull = (remaining === null);
        remaining = (j.remaining === null) ? null : Math.max(0, j.remaining|0);
        total = remaining;

        // update pill
        pill.textContent = j.locked ? "LOCKED" : "UNLOCKED";
        pill.className = "text-xs px-2 py-0.5 rounded-full " + (j.locked ? "bg-rose-600/30 text-rose-300" : "bg-emerald-600/30 text-emerald-300");

        // update "until …"
        if (untilSpan) {
          untilSpan.textContent = j.unlock_at_fmt ? ("until " + j.unlock_at_fmt) : "";
        }

        if(wasNull && remaining != null){ cd.textContent = fmt(remaining); }
      }catch(e){}
    }

    tick(); setInterval(tick, 1000); setInterval(refresh, 10000);
  </script>
</body></html>
""",

"journal": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Journal</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-4xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Journal</h2>
      <a href="{{ url_for('dashboard') }}" class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700">Back</a>
    </div>

    {% if current_user.role=='sub' %}
    <!-- New Entry -->
    <form method="post" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label class="block"><span class="text-sm text-zinc-300">Mood</span>
        <input name="mood" placeholder="Happy, stressed, tired..." class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="block"><span class="text-sm text-zinc-300">Tags</span>
        <input name="tags" placeholder="reflection, rules, tasks..." class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="block"><span class="text-sm text-zinc-300">Entry</span>
        <textarea name="content" rows="5" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"></textarea>
      </label>
      <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Save Entry</button>
    </form>
    {% endif %}

    <!-- Timeline -->
    <div class="space-y-4">
      {% for e in entries %}
      <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4">
        <div class="flex justify-between items-start">
          <div>
            <div class="font-semibold text-lg">Entry {{ e.id }}</div>
            <div class="text-sm text-zinc-400">{{ fmt_dt(e.created_at) }}</div>
            {% if e.mood %}<div class="text-sm text-emerald-300">Mood: {{ e.mood }}</div>{% endif %}
            {% if e.tags %}<div class="text-xs text-zinc-400">Tags: {{ e.tags }}</div>{% endif %}
          </div>
          {% if current_user.role=='dom' %}
          <!-- Dom comment -->
          <form method="post" class="flex gap-2">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="jid" value="{{ e.id }}">
            <input name="comment" placeholder="Write comment..." class="rounded bg-zinc-800/70 border border-white/10 px-2 py-1"/>
            <button class="rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-1">Send</button>
          </form>
          {% endif %}
        </div>
        <p class="mt-3 text-zinc-200 whitespace-pre-line">{{ e.content }}</p>

        {% for c in e.comments %}
        <div class="mt-2 text-sm text-zinc-400 border-l-2 border-indigo-500 pl-3">
          <span class="font-semibold text-indigo-300">
            {{ c.dom.username|default('Dom', true) }}
          </span>:
          {{ c.content }}
          <span class="text-xs text-zinc-500">({{ fmt_dt(c.created_at) }})</span>
        </div>
        {% endfor %}
      </div>
      {% else %}
      <p class="text-zinc-400">No journal entries yet.</p>
      {% endfor %}
    </div>
  </div>
</body></html>
""",

"checkins": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Check-ins</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-3xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Check-ins</h2>
      <div class="flex items-center gap-2">
        <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 {{ 'opacity-60' if rng!='7d' else '' }}" href="{{ url_for('checkins', range='7d') }}">7d</a>
        <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 {{ 'opacity-60' if rng!='30d' else '' }}" href="{{ url_for('checkins', range='30d') }}">30d</a>
        <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 {{ 'opacity-60' if rng!='all' else '' }}" href="{{ url_for('checkins', range='all') }}">All</a>
        <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
      </div>
    </div>

    {% if stats %}
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 grid sm:grid-cols-3 gap-3">
      <div>
        <div class="text-xs text-zinc-400">Entries</div>
        <div class="text-2xl font-semibold">{{ stats.total }}</div>
      </div>
      <div>
        <div class="text-xs text-zinc-400">Avg Energy</div>
        <div class="text-2xl font-semibold">{{ '%.1f'|format(stats.avg_energy) if stats.avg_energy is not none else '—' }}</div>
      </div>
      <div>
        <div class="text-xs text-zinc-400">Avg Sleep</div>
        <div class="text-2xl font-semibold">{{ '%.1f'|format(stats.avg_sleep) if stats.avg_sleep is not none else '—' }} h</div>
      </div>
      {% if stats.moods %}
      <div class="sm:col-span-3 pt-2 text-sm text-zinc-300">
        Top moods:
        {% for m,c in stats.moods %}
          <span class="inline-flex items-center gap-1 rounded-full bg-white/5 px-2 py-0.5 mr-1">{{ m }}<span class="text-zinc-400">{{ c }}</span></span>
        {% endfor %}
      </div>
      {% endif %}
    </div>
    {% endif %}

    {% if current_user.role == 'sub' %}
    <form method="post" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 grid md:grid-cols-3 gap-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

      <div class="md:col-span-3">
        <div class="text-xs text-zinc-400 mb-1">Quick moods</div>
        <div class="flex flex-wrap gap-2">
          {% for m in ['ok','happy','overwhelmed','tired','stressed','focused'] %}
            <button type="button" class="rounded-xl bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 text-sm"
                    onclick="document.querySelector('[name=mood]').value='{{ m }}'">{{ m }}</button>
          {% endfor %}
        </div>
      </div>

      <label><span class="text-sm text-zinc-300">Mood</span>
        <input name="mood" placeholder="ok/overwhelmed/etc" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>

      <label><span class="text-sm text-zinc-300">Energy (1–5)</span>
        <input name="energy" type="number" min="1" max="5" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>

      <label><span class="text-sm text-zinc-300">Sleep hours</span>
        <input name="sleep_hours" type="number" step="0.5" min="0" max="16" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>

      <label class="md:col-span-3"><span class="text-sm text-zinc-300">Tags</span>
        <input name="tags" placeholder="school, work, gym" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>

      <label class="flex items-center gap-2 text-sm text-zinc-300">
        <input type="checkbox" name="is_private" class="rounded bg-zinc-800 border-white/10">
        Keep this check-in private (hidden from Dom)
      </label>

      <label class="md:col-span-3"><span class="text-sm text-zinc-300">Note</span>
        <textarea name="note" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"></textarea>
      </label>

      <div class="md:col-span-3">
        <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Submit</button>
      </div>
    </form>
    {% endif %}

    <ul class="space-y-2">
      {% for c in items %}
      <li class="p-3 rounded-xl bg-zinc-900/50 ring-1 ring-white/10">
        <div class="flex items-center justify-between">
          <div class="text-sm text-zinc-400">{{ fmt_dt(c.created_at) }}</div>
          <div class="flex items-center gap-2">
            {% if c.is_private %}
              <span class="text-xs px-2 py-0.5 rounded-full bg-amber-600/30 text-amber-300">private</span>
            {% endif %}
            <form method="post" action="{{ url_for('checkin_delete', cid=c.id) }}">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <button class="text-xs px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700">delete</button>
            </form>
          </div>
        </div>
        <div class="font-medium mt-1">{{ c.mood or '—' }}</div>
        <div class="text-sm text-zinc-300">{{ c.note }}</div>
        <div class="text-xs text-zinc-400 mt-1">
          {% if c.energy is not none %}Energy {{ c.energy }} · {% endif %}
          {% if c.sleep_hours is not none %}Sleep {{ '%.1f'|format(c.sleep_hours) }}h · {% endif %}
          {% if c.tags %}Tags: {{ c.tags }}{% endif %}
        </div>
      </li>
      {% else %}
      <li class="text-zinc-400">No check-ins yet.</li>
      {% endfor %}
    </ul>
  </div>
</body></html>
""",


"consent": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Consent</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-3xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Consent</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-5">
      <p class="mb-3">Status:
        <strong class="{{ 'text-emerald-300' if c.agreed else 'text-amber-300' }}">{{ 'AGREED' if c.agreed else 'PENDING' }}</strong>
        {% if c.agreed_at %}<span class="text-zinc-400"> ({{ fmt_dt(c.agreed_at) }})</span>{% endif %}
      </p>
      {% if current_user.role=='sub' %}
      <form method="post" class="grid md:grid-cols-2 gap-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label><span class="text-sm text-zinc-300">Yellow word</span>
          <input name="yellow" value="{{ c.safeword_yellow }}" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <label><span class="text-sm text-zinc-300">Red word</span>
          <input name="red" value="{{ c.safeword_red }}" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <div class="md:col-span-2">
          <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">I Agree</button>
        </div>
      </form>
      {% endif %}
      <p class="text-sm text-zinc-400 mt-4">{{ get_flashed_messages() }}</p>
    </div>
  </div>
</body></html>
""",

"users": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Users</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-5xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">User Admin</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>

    <!-- Invites -->
    <section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-4">
      <h3 class="text-lg font-semibold">Invites</h3>
      <form method="post" class="grid md:grid-cols-5 gap-3">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="create_invite">
        <label class="md:col-span-2 text-sm">
          <span>Max uses</span>
          <input name="max_uses" type="number" min="1" max="50" value="1"
                 class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <label class="md:col-span-2 text-sm">
          <span>Expires in (hours)</span>
          <input name="expires_hours" type="number" min="0" placeholder="72"
                 class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <div class="md:col-span-1 flex items-end">
          <button class="w-full rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Create Invite</button>
        </div>
      </form>

<div class="rounded-xl overflow-hidden ring-1 ring-white/10">
  <table class="w-full text-sm">
    <thead class="bg-zinc-900/90">
      <tr class="text-left">
        <th class="px-3 py-2">Code</th>
        <th class="px-3 py-2">Link</th>
        <th class="px-3 py-2">Uses</th>
        <th class="px-3 py-2">Expires</th>
        <th class="px-3 py-2">Status</th>
        <th class="px-3 py-2"></th>
      </tr>
    </thead>
    <tbody class="divide-y divide-white/5">
      {% for i in invites %}
        {% set expired = (i.expires_at and i.expires_at < now) %}
        <tr class="hover:bg-white/5">
          <td class="px-3 py-2 font-mono text-xs">{{ i.code }}</td>
          <td class="px-3 py-2">
            <div class="flex items-center gap-2">
              <input readonly
                     class="copy-input w-full text-xs rounded bg-zinc-800/70 border border-white/10 px-2 py-1"
                     value="{{ url_for('pair_invite_view', code=i.code, _external=True) }}">
              <button type="button"
                      class="copy-btn text-xs rounded bg-zinc-700 hover:bg-zinc-600 px-2 py-1"
                      data-link="{{ url_for('pair_invite_view', code=i.code, _external=True) }}">
                Copy
              </button>
            </div>
          </td>
          <td class="px-3 py-2">{{ i.used_count }}/{{ i.max_uses }}</td>
          <td class="px-3 py-2">{{ i.expires_at or '—' }}</td>
          <td class="px-3 py-2">
            {% if i.disabled %}<span class="text-rose-300">revoked</span>
            {% elif expired %}<span class="text-amber-300">expired</span>
            {% elif i.used_count >= i.max_uses %}<span class="text-zinc-400">used</span>
            {% else %}<span class="text-emerald-300">active</span>{% endif %}
          </td>
          <td class="px-3 py-2">
            {% if not i.disabled and not expired and i.used_count < i.max_uses %}
              <form method="post" class="inline">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <input type="hidden" name="action" value="revoke_invite">
                <input type="hidden" name="code" value="{{ i.code }}">
                <button class="text-sm rounded bg-zinc-700 hover:bg-zinc-600 px-2 py-1">Revoke</button>
              </form>
            {% endif %}
          </td>
        </tr>
      {% else %}
        <tr><td class="px-3 py-3 text-zinc-400" colspan="6">No invites yet.</td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>
    </section>

<!-- Members -->
<section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-3">
  <h3 class="text-lg font-semibold">Pair Members</h3>
  <div class="rounded-xl overflow-hidden ring-1 ring-white/10">
    <table class="w-full text-sm">
      <thead class="bg-zinc-900/90">
        <tr class="text-left">
          <th class="px-3 py-2">ID</th>
          <th class="px-3 py-2">Email</th>
          <th class="px-3 py-2">Name</th>
          <th class="px-3 py-2">Role</th>
          <th class="px-3 py-2">Status</th>
          <th class="px-3 py-2"></th>
        </tr>
      </thead>
      <tbody class="divide-y divide-white/5">
        {% for u in members %}
          <tr class="hover:bg-white/5">
            <td class="px-3 py-2">{{ u.id }}</td>
            <td class="px-3 py-2">{{ u.email }}</td>
            <td class="px-3 py-2">{{ u.name }}</td>
            <td class="px-3 py-2">{{ u.role }}</td>
            <td class="px-3 py-2">
              {% if u.active %}<span class="text-emerald-300">active</span>
              {% else %}<span class="text-rose-300">disabled</span>{% endif %}
            </td>
            <td class="px-3 py-2 text-right">
              {% if u.role == 'sub' and u.active and u.id != current_user.id %}
                <form method="post" class="inline">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                  <input type="hidden" name="action" value="unbind_user">
                  <input type="hidden" name="uid" value="{{ u.id }}">
                  <button class="text-sm rounded bg-rose-700/70 hover:bg-rose-600/70 px-2 py-1">
                    Unbind & Disable
                  </button>
                </form>
              {% elif u.role == 'sub' and not u.active %}
                <form method="post" class="inline">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                  <input type="hidden" name="action" value="reactivate_user">
                  <input type="hidden" name="uid" value="{{ u.id }}">
                  <button class="text-sm rounded bg-zinc-700 hover:bg-zinc-600 px-2 py-1">
                    Reactivate
                  </button>
                </form>
              {% endif %}
            </td>
          </tr>
        {% else %}
          <tr><td class="px-3 py-3 text-zinc-400" colspan="6">No members yet.</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>

    <!-- Manual create / reset (optional) -->
    <section class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 grid md:grid-cols-5 gap-4">
      <form method="post" class="md:col-span-5 grid md:grid-cols-5 gap-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="create_user">
        <label class="md:col-span-2"><span class="text-sm text-zinc-300">Email</span>
          <input name="email" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <label class="md:col-span-1"><span class="text-sm text-zinc-300">Name</span>
          <input name="name" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <label class="md:col-span-1"><span class="text-sm text-zinc-300">Role</span>
          <select name="role" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2">
            <option value="sub" selected>sub</option>
            <option value="dom">dom</option>
          </select>
        </label>
        <label class="md:col-span-5"><span class="text-sm text-zinc-300">Password</span>
          <input name="password" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <div class="md:col-span-5">
          <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Create User (bound to your pair)</button>
        </div>
      </form>

      <form method="post" class="md:col-span-5 grid md:grid-cols-5 gap-4">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="hidden" name="action" value="reset">
        <label class="md:col-span-2"><span class="text-sm text-zinc-300">Email</span>
          <input name="email" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <label class="md:col-span-3"><span class="text-sm text-zinc-300">New Password</span>
          <input name="password" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <div class="md:col-span-5">
          <button class="rounded-xl bg-amber-600 hover:bg-amber-500 px-4 py-2">Reset Password</button>
        </div>
      </form>
    </section>

    <!-- Flashes -->
    {% with msgs = get_flashed_messages(with_categories=true) %}
      {% if msgs %}
        <div class="space-y-2">
          {% for cat, m in msgs %}
            <div class="rounded-lg px-3 py-2 text-sm ring-1
              {% if cat == 'error' %} bg-rose-900/40 ring-rose-700/40 text-rose-200
              {% elif cat == 'success' %} bg-emerald-900/40 ring-emerald-700/40 text-emerald-200
              {% else %} bg-zinc-900/70 ring-white/10 text-zinc-200 {% endif %}">
              {{ m }}
            </div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
  </div>
  <script>
(function () {
  document.addEventListener("click", function (e) {
    const inp = e.target.closest("input.copy-input");
    if (inp) { inp.select(); }
  });

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.focus(); ta.select();
      try { document.execCommand("copy"); } finally { document.body.removeChild(ta); }
    }
  }

  document.addEventListener("click", async function (e) {
    const btn = e.target.closest("button.copy-btn");
    if (!btn) return;
    const link = btn.dataset.link || "";
    const original = btn.textContent;
    try {
      await copyText(link);
      btn.textContent = "Copied!";
      btn.classList.replace("bg-zinc-700", "bg-emerald-700");
      setTimeout(() => {
        btn.textContent = original;
        btn.classList.replace("bg-emerald-700", "bg-zinc-700");
      }, 1200);
    } catch {
      btn.textContent = "Press Ctrl+C";
      setTimeout(() => { btn.textContent = original; }, 1500);
    }
  });
})();
</script>
</body></html>
""",


"settings": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Settings</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-2xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Settings</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>

    <!-- Profile & Preferences -->
    <form method="post" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

      <div class="grid md:grid-cols-2 gap-4">
        <label class="block">
          <span class="text-sm text-zinc-300">Display name</span>
          <input name="name" value="{{ current_user.name }}" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Email</span>
          <input name="email" value="{{ current_user.email }}" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
        </label>
      </div>

      <div class="grid md:grid-cols-3 gap-4">
        <label class="block">
          <span class="text-sm text-zinc-300">Theme</span>
          <select name="theme" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2">
            <option value="dark" {{ 'selected' if (current_user.theme or 'dark')=='dark' else '' }}>Dark</option>
            <option value="light" {{ 'selected' if (current_user.theme or 'dark')=='light' else '' }}>Light</option>
            <option value="system" {{ 'selected' if (current_user.theme or 'dark')=='system' else '' }}>System</option>
          </select>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Date format</span>
          <select name="date_format" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2">
            <option value="YYYY-MM-DD" {{ 'selected' if (current_user.date_format or 'YYYY-MM-DD')=='YYYY-MM-DD' else '' }}>YYYY-MM-DD</option>
            <option value="DD/MM/YYYY" {{ 'selected' if (current_user.date_format or 'YYYY-MM-DD')=='DD/MM/YYYY' else '' }}>DD/MM/YYYY</option>
            <option value="MM/DD/YYYY" {{ 'selected' if (current_user.date_format or 'YYYY-MM-DD')=='MM/DD/YYYY' else '' }}>MM/DD/YYYY</option>
          </select>
        </label>
        <label class="block">
          <span class="text-sm text-zinc-300">Time</span>
          <div class="mt-2 flex items-center gap-2 text-sm">
            <input type="checkbox" name="time_format_24h" {{ 'checked' if current_user.time_format_24h else '' }} class="rounded bg-zinc-800 border-white/10">
            <span>Use 24-hour clock</span>
          </div>
        </label>
      </div>

      <div class="grid md:grid-cols-2 gap-4">
        <label class="block">
          <span class="text-sm text-zinc-300">Notifications</span>
          <div class="mt-2 space-y-2 text-sm">
            <label class="flex items-center gap-2">
              <input type="checkbox" name="notify_lock_changes" {{ 'checked' if current_user.notify_lock_changes else '' }} class="rounded bg-zinc-800 border-white/10">
              <span>Lock state changes</span>
            </label>
            <label class="flex items-center gap-2">
              <input type="checkbox" name="notify_task_events" {{ 'checked' if current_user.notify_task_events else '' }} class="rounded bg-zinc-800 border-white/10">
              <span>Task assigned / verified</span>
            </label>
          </div>
        </label>

      <label class="block">
        <span class="text-sm text-zinc-300">Session</span>
        <a href="{{ url_for('logout') }}"
          class="mt-2 block w-full text-center rounded-xl bg-rose-600 hover:bg-rose-500 px-4 py-2 text-sm">
          Log out
        </a>
      </label>

      </div>

      <div>
        <button class="rounded-xl bg-emerald-600 hover:bg-emerald-500 px-4 py-2">Save Settings</button>
      </div>
    </form>

    <!-- Change Password -->
    <form method="post" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 space-y-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <input type="hidden" name="change_password" value="1">
      <label class="block"><span class="text-sm text-zinc-300">Current password</span>
        <input type="password" name="current" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="block"><span class="text-sm text-zinc-300">New password</span>
        <input type="password" name="new" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <label class="block"><span class="text-sm text-zinc-300">Confirm new password</span>
        <input type="password" name="confirm" required class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>
      <button class="w-full rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Update Password</button>
    </form>

    <p class="text-sm text-zinc-400">{{ get_flashed_messages() }}</p>
  </div>
</body></html>
""",














"audit": """
<!doctype html><html><head>
<meta charset="utf-8"/><title>Audit Log</title>
<script src="https://cdn.tailwindcss.com"></script>
</head><body class="bg-zinc-950 text-zinc-100 min-h-screen">
  <div class="max-w-6xl mx-auto px-4 py-6 space-y-6">
    <div class="flex items-center justify-between">
      <h2 class="text-xl font-semibold">Audit Log</h2>
      <a class="text-sm px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700" href="{{ url_for('dashboard') }}">Back</a>
    </div>

    <!-- Filters -->
    <form method="get" class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 p-4 grid md:grid-cols-5 gap-3">
      <label class="text-sm">
        <span class="text-zinc-300">Action</span>
        <select name="action" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2">
          <option value="">Any</option>
          {% for a in actions %}
            <option value="{{ a }}" {{ 'selected' if sel_action==a else '' }}>{{ a }}</option>
          {% endfor %}
        </select>
      </label>
      <label class="text-sm">
        <span class="text-zinc-300">Target</span>
        <select name="target" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2">
          <option value="">Any</option>
          {% for t in targets %}
            <option value="{{ t }}" {{ 'selected' if sel_target==t else '' }}>{{ t }}</option>
          {% endfor %}
        </select>
      </label>
      <label class="text-sm">
        <span class="text-zinc-300">User</span>
        <select name="user_id" class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2">
          <option value="">Any</option>
          {% for u in users %}
            <option value="{{ u.id }}" {{ 'selected' if sel_user==u.id|string else '' }}>{{ u.name }} ({{ u.email }})</option>
          {% endfor %}
        </select>
      </label>
      <label class="md:col-span-2 text-sm">
        <span class="text-zinc-300">Search (target/details)</span>
        <input name="q" value="{{ q }}" placeholder="e.g. punishment, lock, verify..."
               class="mt-1 w-full rounded-xl bg-zinc-800/70 border border-white/10 px-3 py-2"/>
      </label>

      <div class="md:col-span-5 flex gap-3">
        <button class="rounded-xl bg-indigo-600 hover:bg-indigo-500 px-4 py-2">Apply</button>
        <a href="{{ url_for('audit_page') }}" class="rounded-xl bg-zinc-800 hover:bg-zinc-700 px-4 py-2">Clear</a>
        <div class="ml-auto text-sm text-zinc-400 self-center">Total: {{ total }}</div>
      </div>
    </form>

    <!-- Table -->
    <div class="rounded-2xl bg-zinc-900/70 ring-1 ring-white/10 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-zinc-900/90">
          <tr class="text-left">
            <th class="px-4 py-3">When</th>
            <th class="px-4 py-3">User</th>
            <th class="px-4 py-3">Action</th>
            <th class="px-4 py-3">Target</th>
            <th class="px-4 py-3">Details</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-white/5">
          {% for a in items %}
          {% set pill = (
            'bg-sky-600/30 text-sky-300' if a.action in ['login','logout'] else
            'bg-rose-600/30 text-rose-300' if a.target=='punishment' and 'status' in a.action else
            'bg-amber-600/30 text-amber-300' if a.target=='lock' else
            'bg-emerald-600/30 text-emerald-300' if a.action in ['verify','complete_punishment'] else
            'bg-white/10 text-zinc-300'
          ) %}
          <tr class="hover:bg-white/5 align-top">
            <td class="px-4 py-3 whitespace-nowrap">{{ fmt_dt(a.created_at) }}</td>
            <td class="px-4 py-3">{{ a.actor_id or '—' }}</td>
            <td class="px-4 py-3">
              <span class="text-xs px-2 py-0.5 rounded-full {{ pill }}">{{ a.action }}</span>
            </td>
            <td class="px-4 py-3">{{ a.target }}</td>
            <td class="px-4 py-3 text-zinc-300">{{ a.details }}</td>
          </tr>
          {% else %}
          <tr><td colspan="5" class="px-4 py-6 text-zinc-400">No entries.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    {% if pages > 1 %}
    <div class="flex items-center justify-center gap-2">
      {% set base = url_for('audit_page', action=sel_action, target=sel_target, user_id=sel_user, q=q) %}
      <a class="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 {{ 'opacity-50 pointer-events-none' if page<=1 }}" href="{{ base }}&page={{ page-1 }}">Prev</a>
      <span class="text-sm text-zinc-400">Page {{ page }} of {{ pages }}</span>
      <a class="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 {{ 'opacity-50 pointer-events-none' if page>=pages }}" href="{{ base }}&page={{ page+1 }}">Next</a>
    </div>
    {% endif %}

  </div>
</body></html>
""",

}

# ---------- Run ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        for u in User.query.all():
            if not (u.session_nonce or "").strip():
                u.session_nonce = secrets.token_hex(8)
        db.session.commit()
    app.run(debug=True)
