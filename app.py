import hmac
import json
import os
import re
import secrets
import sqlite3
import time

import pandas as pd
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, Response, session, url_for)
from google import genai
from google.genai import types as genai_types
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)  # on a server, point this at a persistent disk
AUTH_DB = os.path.join(DATA_DIR, "auth.db")          # user accounts
USER_DIR = os.path.join(DATA_DIR, "user_data")        # one data file per user

app = Flask(__name__)
# Signs the login cookie. If not set, a new random key is created each time the app starts,
# which just means everyone has to log in again after a restart.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit
# Cookie settings for a public site. Lax stops other websites from using a logged-in
# session to submit forms here (for example, deleting a dataset). Secure makes the
# cookie HTTPS-only; set COOKIE_SECURE=1 on the server, but not on your own computer.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"

# Sign-up needs this invite code. If it isn't set, new accounts can't be created.
SIGNUP_CODE = os.environ.get("SIGNUP_CODE", "")

NUMERIC_TYPES = {"INTEGER", "REAL", "NUMERIC", "FLOAT", "DOUBLE"}
CHART_TYPES = {"bar", "line", "pie"}
ALL_CHARTS = CHART_TYPES | {"table"}
MAX_TABLES = 4  # how many datasets one question can combine
DATE_HINTS = ("date", "month", "year", "time", "day")
# Words that would change or remove data, or attach other databases. Queries containing them are rejected.
FORBIDDEN_SQL = re.compile(
    r"\b(insert|update|delete|drop|alter|create|replace|pragma|attach|detach|vacuum)\b",
    re.IGNORECASE,
)


# ---------- Storage ----------

def init_storage():
    """Create the accounts table and the per-user data folder if they don't exist."""
    os.makedirs(USER_DIR, exist_ok=True)
    conn = sqlite3.connect(AUTH_DB)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        conn.close()


def auth_conn():
    return sqlite3.connect(AUTH_DB)


def user_db_path(user_id) -> str:
    return os.path.join(USER_DIR, f"user_{int(user_id)}.db")


def get_conn():
    """Open the logged-in user's own data file. Users never see each other's datasets."""
    user_id = session.get("user_id")
    if not user_id:
        abort(401)
    return sqlite3.connect(user_db_path(user_id))


def safe_name(text: str) -> str:
    """Turn any text into a safe SQL name: lowercase letters, digits, underscores."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", str(text).strip().lower())
    name = re.sub(r"_+", "_", name).strip("_")
    if not name:
        name = "data"
    if name[0].isdigit():
        name = "t_" + name
    return name


def list_tables() -> list[str]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
    finally:
        conn.close()
    return [r[0] for r in rows]


def get_columns(table: str) -> list[tuple[str, str]]:
    """Return (column_name, column_type) pairs for a table."""
    conn = get_conn()
    try:
        rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    finally:
        conn.close()
    return [(r[1], (r[2] or "").upper()) for r in rows]


def column_groups(table: str):
    """Return (all names, numeric names, text names, date-like names) for a table."""
    cols = get_columns(table)
    names = [c for c, _ in cols]
    numeric = [c for c, t in cols if t in NUMERIC_TYPES]
    text = [c for c, t in cols if t not in NUMERIC_TYPES]
    dates = [c for c in names if any(h in c for h in DATE_HINTS)]
    return names, numeric, text, dates


def build_suggestions(tables: list[str]) -> tuple[list[str], str]:
    """Starter questions. Returns (questions, hint). The hint explains why joining isn't possible."""
    if len(tables) == 1:
        table = tables[0]
        _, numeric, text, dates = column_groups(table)
        ideas = []
        if numeric and text:
            ideas.append(f"What is the total {numeric[0]} by {text[0]}?")
            ideas.append(f"Which {text[0]} has the highest {numeric[0]}?")
        if dates and numeric:
            ideas.append(f"How has {numeric[0]} changed over {dates[0]}?")
        if text:
            ideas.append(f"How many rows are there for each {text[0]}?")
        if numeric and text:
            ideas.append(f"What share of {numeric[0]} does each {text[0]} make up?")
        return ideas[:4], ""

    # Several datasets: find a column name that every selected dataset has.
    name_sets = [set(column_groups(t)[0]) for t in tables]
    shared = [c for c in column_groups(tables[0])[0] if all(c in s for s in name_sets)]
    if not shared:
        return [], ("These datasets have no column name in common, so they can't be joined. "
                    "Add a column with the same name to each file, such as region.")

    key = shared[0]
    first, second = tables[0], tables[1]
    _, numeric1, _, _ = column_groups(first)
    _, numeric2, _, _ = column_groups(second)
    ideas = []
    if numeric1 and numeric2:
        ideas.append(f"Compare {numeric1[0]} in {first} with {numeric2[0]} in {second} for each {key}.")
        ideas.append(f"Which {key} has the largest gap between {numeric1[0]} in {first} and {numeric2[0]} in {second}?")
    elif numeric1:
        ideas.append(f"What is the total {numeric1[0]} for each {key} across the selected datasets?")
    ideas.append(f"How many rows does each {key} have across the selected datasets?")
    return ideas[:4], ""


# ---------- Accounts and login ----------

PUBLIC_ENDPOINTS = {"login", "register", "static"}

# Blocks guessing passwords: after 5 failed logins from one address, that address
# waits 15 minutes. Kept in memory, so it resets when the server restarts.
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60
failed_logins: dict[str, list[float]] = {}


def client_ip() -> str:
    # Hosting services add the real visitor address to the end of X-Forwarded-For.
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[-1].strip() or (request.remote_addr or "unknown")


def too_many_failed_logins(ip: str) -> bool:
    now = time.time()
    recent = [t for t in failed_logins.get(ip, []) if now - t < LOCKOUT_SECONDS]
    failed_logins[ip] = recent
    return len(recent) >= MAX_FAILED_LOGINS


@app.before_request
def require_login():
    """Every page and API needs a logged-in user, except the login and sign-up pages."""
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if not session.get("user_id"):
        return redirect(url_for("login", next=request.path))
    return None


def start_session(user_id, username):
    session.clear()
    session["user_id"] = user_id
    session["username"] = username


def safe_next(next_url: str) -> str:
    """Only allow redirects within this site."""
    if not next_url.startswith("/") or next_url.startswith("//"):
        return url_for("index")
    return next_url


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = client_ip()
        if too_many_failed_logins(ip):
            return render_template(
                "login.html",
                error="Too many failed attempts. Wait 15 minutes and try again.",
                signup_open=bool(SIGNUP_CODE),
            ), 429
        conn = auth_conn()
        try:
            row = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        finally:
            conn.close()
        if row and check_password_hash(row[2], password):
            failed_logins.pop(ip, None)
            start_session(row[0], row[1])
            return redirect(safe_next(request.args.get("next", "")))
        failed_logins.setdefault(ip, []).append(time.time())
        error = "Wrong username or password."

    return render_template("login.html", error=error, signup_open=bool(SIGNUP_CODE))


@app.route("/register", methods=["GET", "POST"])
def register():
    if not SIGNUP_CODE:
        return render_template("register.html", error=None, closed=True)

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        code = request.form.get("code", "")

        if not hmac.compare_digest(code, SIGNUP_CODE):
            error = "The invite code is wrong."
        elif not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            error = "Username must be 3 to 30 letters, numbers, dots, dashes or underscores."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            conn = auth_conn()
            try:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                conn.commit()
                new_id = cur.lastrowid
            except sqlite3.IntegrityError:
                error = "That username is already taken."
                new_id = None
            finally:
                conn.close()
            if new_id:
                start_session(new_id, username)
                return redirect(url_for("index"))

    return render_template("register.html", error=error, closed=False)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Pages ----------

@app.route("/")
def index():
    return render_template("index.html", tables=list_tables())


@app.route("/ask")
def ask_page():
    tables = list_tables()
    # ?table=a&table=b selects one or more datasets.
    selected = [t for t in request.args.getlist("table") if t in tables][:MAX_TABLES]
    if not selected and tables:
        selected = [tables[0]]
    suggestions, join_hint = build_suggestions(selected) if selected else ([], "")
    return render_template(
        "ask.html",
        tables=tables,
        selected=selected,
        suggestions=suggestions,
        join_hint=join_hint,
        max_tables=MAX_TABLES,
    )


@app.route("/table/<name>")
def view_table(name):
    if name not in list_tables():
        abort(404)

    cols = get_columns(name)
    conn = get_conn()
    try:
        total = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        preview = pd.read_sql_query(f'SELECT * FROM "{name}" LIMIT 20', conn)
    finally:
        conn.close()

    return render_template(
        "table.html",
        name=name,
        total=total,
        columns=[c for c, _ in cols],
        numeric=[c for c, t in cols if t in NUMERIC_TYPES],
        preview=preview.fillna("").to_dict(orient="records"),
    )


# ---------- Upload and delete ----------

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Please choose a file.")
        return redirect(url_for("index"))
    if not file.filename.lower().endswith(".csv"):
        flash("Only .csv files are supported.")
        return redirect(url_for("index"))

    try:
        df = pd.read_csv(file)
    except Exception as exc:
        flash(f"Could not read the CSV: {exc}")
        return redirect(url_for("index"))

    if df.empty or len(df.columns) == 0:
        flash("The file has no data rows.")
        return redirect(url_for("index"))

    df.columns = [safe_name(c) for c in df.columns]
    table = safe_name(os.path.splitext(file.filename)[0])

    conn = get_conn()
    try:
        # Uploading a file with the same name replaces the old dataset.
        df.to_sql(table, conn, if_exists="replace", index=False)
    finally:
        conn.close()

    flash(f"Uploaded {len(df)} rows into '{table}'. Click it below to ask questions.")
    # Return to the dataset list, where the new dataset can be opened.
    return redirect(url_for("index"))


@app.route("/delete/<name>", methods=["POST"])
def delete_table(name):
    if name not in list_tables():
        abort(404)

    conn = get_conn()
    try:
        conn.execute(f'DROP TABLE "{name}"')
        conn.commit()
    finally:
        conn.close()

    flash(f"Deleted '{name}'.")
    return redirect(url_for("index"))


# ---------- Questions ----------

def table_context(tables: list[str]) -> str:
    """Describe each table's columns and a few sample rows for the AI."""
    parts = []
    conn = get_conn()
    try:
        for table in tables:
            cols = get_columns(table)
            sample = pd.read_sql_query(f'SELECT * FROM "{table}" LIMIT 3', conn).to_string(index=False)
            column_text = ", ".join(f"{c} ({t or 'TEXT'})" for c, t in cols)
            parts.append(f"Table: {table}\nColumns: {column_text}\nSample rows:\n{sample}")
    finally:
        conn.close()
    return "\n\n".join(parts)


def ask_gemini(tables: list[str], question: str, previous: dict | None = None) -> dict:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set on this computer.")

    followup_text = ""
    if previous:
        followup_text = f"""
This is a follow-up to an earlier question.
Earlier question: "{previous['question']}"
Earlier SQL query:
{previous['sql']}

The new request changes that result, for example by a different grouping, time period, filter or chart.
Write a new SELECT query that applies the change to the earlier query. Keep the same kind of answer unless the request asks otherwise.
"""

    client = genai.Client(api_key=api_key)
    prompt = f"""You are a data analyst. Write one SQLite SELECT query that answers the question.

The question may use one or more of these tables:

{table_context(tables)}

Question: {question}
{followup_text}
Rules:
- Use only the tables and columns listed above.
- If the question uses more than one table, combine them with JOIN on a column they share (for example region).
- When a column name exists in more than one table, prefix it with the table name, for example sales.region.
- Write a single SELECT statement. Never change data.
- Put the group label (such as region) in the first column. Put each number in its own column after it, with a clear alias.
- Choose the chart that best shows the answer: "line" for changes over time, "pie" for shares of a whole (only a few groups), "bar" for comparisons, and "table" if none of these fit.

Return JSON with these keys:
- "sql": the SELECT query
- "title": a short title for the result
- "chart": one of "bar", "line", "pie", "table"
"""
    last_error = None
    # If Google is busy (503) or rate-limited (429), wait and try again.
    for attempt in range(5):
        try:
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            return json.loads(response.text)
        except Exception as exc:
            last_error = exc
            message = str(exc)
            busy = "503" in message or "UNAVAILABLE" in message or "429" in message
            if not busy:
                raise
            time.sleep(3 * (2 ** attempt))  # waits 3, 6, 12, 24, 48 seconds

    raise RuntimeError(
        "Google's AI service is busy right now. Please try again in a few minutes."
    ) from last_error


def write_insight(question: str, df: pd.DataFrame) -> str:
    """Ask Gemini for a short plain-English insight. Returns "" if it can't."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return ""

    prompt = f"""A business user asked: "{question}"

The query returned these rows:
{df.head(20).to_string(index=False)}

Write one or two short sentences in plain English that a manager would find useful.
Mention the most important number or comparison. Use only the figures shown above.
Do not use markdown or bullet points."""

    client = genai.Client(api_key=api_key)
    # Short answer and few retries: the insight is a bonus, so if Google is busy
    # we fall back to the plain summary quickly instead of making the user wait.
    for attempt in range(2):
        try:
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=150,
                ),
            )
            return (response.text or "").strip()
        except Exception as exc:
            message = str(exc)
            busy = "503" in message or "UNAVAILABLE" in message or "429" in message
            if not busy:
                return ""
            time.sleep(3)
    return ""


# ---------- Shared helpers for the question API ----------

def parse_tables(payload: dict) -> tuple[list[str], str]:
    """Return (tables, error). Checks that every dataset belongs to the logged-in user."""
    tables = payload.get("tables")
    if tables is None and payload.get("table"):
        tables = [payload["table"]]
    if not isinstance(tables, list):
        tables = []
    tables = list(dict.fromkeys(tables))  # remove duplicates, keep order

    known = list_tables()
    if not tables or any(t not in known for t in tables):
        return [], "Please choose at least one dataset."
    if len(tables) > MAX_TABLES:
        return [], f"You can combine up to {MAX_TABLES} datasets at once."
    return tables, ""


def clean_sql(raw) -> str:
    return str(raw or "").strip().rstrip(";").strip()


def check_sql(sql: str) -> str:
    """Return an error message if the query may not run, otherwise an empty string."""
    if not sql:
        return "The query is empty."
    if not sql.lower().startswith("select") or ";" in sql or FORBIDDEN_SQL.search(sql):
        return "Only a single SELECT query can run, and it must not change data."
    return ""


def run_query(sql: str) -> pd.DataFrame:
    conn = get_conn()
    try:
        conn.execute("PRAGMA query_only = ON")  # extra protection: read-only
        return pd.read_sql_query(sql, conn)
    finally:
        conn.close()


def build_result(df: pd.DataFrame, chart: str, title: str, question: str, sql: str) -> dict:
    label_col = df.columns[0]
    # Every numeric column after the first becomes one series in the chart.
    num_cols = [c for c in df.columns[1:] if pd.api.types.is_numeric_dtype(df[c])]

    if chart in CHART_TYPES and num_cols:
        num_cols = num_cols[:3]
        datasets = [
            {"label": c, "values": df[c].fillna(0).round(2).tolist()}
            for c in num_cols
        ]
        if chart == "pie":
            datasets = datasets[:1]

        series = df[num_cols[0]].fillna(0)
        top_idx = series.idxmax()
        top_label = str(df.loc[top_idx, label_col])
        top_value = round(float(series.loc[top_idx]), 2)
        result = {
            "chart": chart,
            "labels": df[label_col].astype(str).tolist(),
            "datasets": datasets,
            "highlight": {"label": top_label, "value": top_value,
                          "caption": f"Highest {num_cols[0]} ({label_col})"},
        }
        summary = f"{top_label} has the highest {num_cols[0]} at {top_value:,.2f}."
    else:
        result = {"chart": "table", "labels": [], "datasets": [], "highlight": None}
        summary = f"{len(df)} rows returned."

    # Use the written insight when available, otherwise the plain summary.
    insight = write_insight(question, df)

    return dict(
        title=title,
        sql=sql,
        summary=insight or summary,
        columns=list(df.columns),
        rows=json.loads(df.head(100).to_json(orient="records")),
        **result,
    )


# ---------- Question API: step 1 writes the query, step 2 runs it ----------

@app.route("/api/plan", methods=["POST"])
def api_plan():
    """Ask Gemini for a query. Nothing runs yet, so the user can review it."""
    payload = request.get_json(silent=True) or {}
    tables, error = parse_tables(payload)
    if error:
        return jsonify(error=error), 400

    question = str(payload.get("question") or "").strip()
    if not question:
        return jsonify(error="Please type a question."), 400

    # Optional: the previous question and its SQL, sent when the user asks a follow-up.
    previous = payload.get("previous")
    if isinstance(previous, dict) and previous.get("sql") and previous.get("question"):
        previous = {
            "question": str(previous["question"])[:500],
            "sql": str(previous["sql"])[:4000],
        }
    else:
        previous = None

    try:
        plan = ask_gemini(tables, question, previous)
    except Exception as exc:
        return jsonify(error=f"Could not get an answer: {exc}"), 500

    sql = clean_sql(plan.get("sql"))
    error = check_sql(sql)
    if error:
        return jsonify(error=error, sql=sql), 400

    chart = plan.get("chart", "table")
    if chart not in ALL_CHARTS:
        chart = "table"
    return jsonify(
        question=question,
        title=str(plan.get("title") or question)[:200],
        sql=sql,
        chart=chart,
    )


@app.route("/api/run", methods=["POST"])
def api_run():
    """Run a query, which may have been edited by the user. It is checked again before running."""
    payload = request.get_json(silent=True) or {}
    tables, error = parse_tables(payload)
    if error:
        return jsonify(error=error), 400

    question = str(payload.get("question") or "").strip()
    sql = clean_sql(payload.get("sql"))
    error = check_sql(sql)
    if error:
        return jsonify(error=error, sql=sql), 400

    chart = payload.get("chart", "table")
    if chart not in ALL_CHARTS:
        chart = "table"
    title = str(payload.get("title") or question or "Result")[:200]

    try:
        df = run_query(sql)
    except Exception as exc:
        return jsonify(error=f"Query failed: {exc}", sql=sql), 500

    if df.empty:
        return jsonify(error="No matching data found.", sql=sql), 200

    return jsonify(build_result(df, chart, title, question, sql))


@app.route("/api/export", methods=["POST"])
def api_export():
    """Return the full result of a query as a CSV file."""
    payload = request.get_json(silent=True) or {}
    tables, error = parse_tables(payload)
    if error:
        return jsonify(error=error), 400

    sql = clean_sql(payload.get("sql"))
    error = check_sql(sql)
    if error:
        return jsonify(error=error), 400

    try:
        df = run_query(sql)
    except Exception as exc:
        return jsonify(error=f"Query failed: {exc}"), 500

    return Response(
        df.to_csv(index=False),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="results.csv"'},
    )


init_storage()

if __name__ == "__main__":
    # host="0.0.0.0" lets other devices on your Wi-Fi reach the app.
    # debug is off because the debug console would be exposed to the network.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
