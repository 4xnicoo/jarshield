## jarshield backend 
## I dont know shit so im using flask

import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import requests as http
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": [
    "https://jarshield.link",
    "https://www.jarshield.link",
    "https://manage.jarshield.link",
]}})

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]

# supabase sign ts JWTs using the raw utf-8 string as the hmac key this is why aint workng
JWT_SECRET = os.environ["SUPABASE_JWT_SECRET"]

SERVICE_HEADERS = {
    "apikey": SERVICE_KEY,
    "Authorization": f"Bearer {SERVICE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}

def db(table):
    return f"{SUPABASE_URL}/rest/v1/{table}"

def db_get(table, params):
    r = http.get(db(table), headers=SERVICE_HEADERS, params=params)
    r.raise_for_status()
    return r.json()

def db_post(table, payload):
    r = http.post(db(table), headers=SERVICE_HEADERS, json=payload)
    r.raise_for_status()
    return r.json()

def db_patch(table, params, payload):
    r = http.patch(db(table), headers=SERVICE_HEADERS, params=params, json=payload)
    r.raise_for_status()
    return r.json()

def db_delete(table, params):
    r = http.delete(db(table), headers=SERVICE_HEADERS, params=params)
    r.raise_for_status()

def log_audit(project_id, user_id, tester_uuid, action, success, reason, ip):
    try:
        http.post(db("audit_logs"), headers=SERVICE_HEADERS, json={
            "project_id": project_id,
            "user_id": user_id,
            "tester_uuid": tester_uuid,
            "action": action,
            "success": success,
            "failure_reason": reason,
            "ip_address": ip,
        })
    except Exception as e:
        print("audit log failed:", e)

JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
try:
    _jwks_client = jwt.PyJWKClient(JWKS_URL, cache_keys=True)
    print(f"JWKS client ready: {JWKS_URL}")
except Exception as e:
    _jwks_client = None
    print(f"JWKS client failed (will fall back to HS256): {e}")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        token = header.split(" ", 1)[1]
        try:
            # jwks rs256
            if _jwks_client:
                signing_key = _jwks_client.get_signing_key_from_jwt(token)
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256"],
                    options={"verify_aud": False},
                    leeway=timedelta(seconds=10),
                )
            else:
                # legacy
                payload = jwt.decode(
                    token,
                    JWT_SECRET,
                    algorithms=["HS256"],
                    options={"verify_aud": False},
                    leeway=timedelta(seconds=10),
                )
            request.user_id = payload["sub"]
            return f(*args, **kwargs)
        except Exception as e:
            # hs256
            try:
                payload = jwt.decode(
                    token,
                    JWT_SECRET,
                    algorithms=["HS256"],
                    options={"verify_aud": False},
                    leeway=timedelta(seconds=10),
                )
                request.user_id = payload["sub"]
                return f(*args, **kwargs)
            except Exception:
                return jsonify({"error": "invalid_token"}), 401
    return decorated

## the above was copy pasted shit because i dont know the supabase stuff good enough

# --- routes ---

@app.route("/api/cli/login", methods=["POST"])
def cli_login():
    data = request.get_json() or {}
    r = http.post(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
        headers={"apikey": SERVICE_KEY},
        json={"email": data.get("email"), "password": data.get("password")}
    )
    return jsonify(r.json()), r.status_code

@app.route("/api/me", methods=["GET"])
@require_auth
def get_me():
    rows = db_get("profiles", {"id": f"eq.{request.user_id}", "select": "*"})
    if not rows:
        return jsonify({"error": "profile_not_found"}), 404
    return jsonify(rows[0])

@app.route("/api/codes/generate", methods=["POST"])
@require_auth
def generate_code():
    data = request.get_json() or {}
    project_name = data.get("project_name", "").strip().lower()
    if not project_name:
        return jsonify({"error": "invalid_project_name"}), 400

    profiles = db_get("profiles", {"id": f"eq.{request.user_id}", "select": "jarshield_uuid"})
    if not profiles:
        return jsonify({"error": "profile_not_found"}), 404
    tester_uuid = profiles[0]["jarshield_uuid"]

    projects = db_get("projects", {"name": f"eq.{project_name}", "select": "id,owner_id,webhook_url,webhook_color,log_generate"})
    if not projects:
        return jsonify({"error": "unauthorized"}), 403
    project = projects[0]
    project_id = project["id"]

    note_str = ""
    is_owner = project["owner_id"] == request.user_id
    if not is_owner:
        testers = db_get("project_testers", {
            "project_id": f"eq.{project_id}",
            "tester_uuid": f"eq.{tester_uuid}",
            "select": "id"
        })
        if not testers:
            return jsonify({"error": "unauthorized"}), 403
        note = testers[0].get("note")
        if note:
            note_str = f' "{note}"'
    else:
        note_str = ' *(Owner)*'

    since = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    recent = db_get("launch_codes", {
        "project_id": f"eq.{project_id}",
        "user_id": f"eq.{request.user_id}",
        "created_at": f"gte.{since}",
        "select": "id"
    })
    if recent:
        return jsonify({"error": "rate_limit_exceeded"}), 429

    raw_code = secrets.token_hex(4).upper()
    code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=15)).isoformat()

    db_post("launch_codes", {
        "project_id": project_id,
        "user_id": request.user_id,
        "tester_uuid": tester_uuid,
        "code_hash": code_hash,
        "expires_at": expires_at,
    })

    log_audit(project_id, request.user_id, tester_uuid, "generate_code", True, None, request.remote_addr)
    
    webhook_url = project.get("webhook_url")
    if webhook_url and project.get("log_generate"):
        webhook_color = project.get("webhook_color") or "#3b82f6"
        try:
            color_int = int(webhook_color.lstrip('#'), 16)
        except Exception:
            color_int = 3900150
            
        embed = {
            "title": f"Code generated: {project_name}",
            "color": color_int,
            "description": f"**Code:** `{raw_code}`\n**User:** `{tester_uuid}`{note_str}\n**Generated on:** <t:{int(datetime.now().timestamp())}:R>",
            "footer": {
                "text": "jarshield audit logs - https://manage.jarshield.link/ • made by 4xnico"
            }
        }
        try:
            http.post(webhook_url, json={"embeds": [embed]}, timeout=2)
        except Exception:
            pass

    return jsonify({"code": raw_code, "expires_in": 15})

def send_incorrect_webhook(project, code):
    webhook_url = project.get("webhook_url")
    if webhook_url and project.get("log_incorrect"):
        embed = {
            "title": "Incorrect code",
            "color": 16711680,
            "description": f"**Code:** `{code}`\n**Entered on:** <t:{int(datetime.now().timestamp())}:R>",
            "footer": {
                "text": "jarshield audit logs - https://manage.jarshield.link/ • made by 4xnico"
            }
        }
        try:
            http.post(webhook_url, json={"embeds": [embed]}, timeout=2)
        except Exception:
            pass

@app.route("/api/codes/validate", methods=["POST"])
def validate_code():
    data = request.get_json(force=True, silent=True) or {}
    project_name = (data.get("project_name") or request.args.get("project_name", "")).strip().lower()
    code = (data.get("code") or request.args.get("code", "")).strip().upper()

    if not project_name or not code or len(code) < 6:
        return jsonify({"success": False, "reason": "invalid_input"}), 400

    projects = db_get("projects", {"name": f"eq.{project_name}", "select": "id,decryption_key,webhook_url,webhook_color,log_play,log_incorrect"})
    if not projects:
        log_audit(None, None, None, "validate_code", False, "project_not_found", request.remote_addr)
        return jsonify({"success": False, "reason": "invalid_code"})

    project_id = projects[0]["id"]
    decryption_key = projects[0].get("decryption_key")
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    codes = db_get("launch_codes", {
        "project_id": f"eq.{project_id}",
        "code_hash": f"eq.{code_hash}",
        "select": "*",
        "limit": "1"
    })
    if not codes:
        log_audit(project_id, None, None, "validate_code", False, "code_not_found", request.remote_addr)
        send_incorrect_webhook(projects[0], code)
        return jsonify({"success": False, "reason": "invalid_code"})

    rec = codes[0]

    if rec.get("code_hash") != code_hash:
        log_audit(project_id, None, None, "validate_code", False, "hash_mismatch", request.remote_addr)
        send_incorrect_webhook(projects[0], code)
        return jsonify({"success": False, "reason": "invalid_code"})

    if rec.get("used_at"):
        log_audit(project_id, rec["user_id"], rec["tester_uuid"], "validate_code", False, "already_used", request.remote_addr)
        send_incorrect_webhook(projects[0], code)
        return jsonify({"success": False, "reason": "invalid_code"})

    expires_at = datetime.fromisoformat(rec["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        log_audit(project_id, rec["user_id"], rec["tester_uuid"], "validate_code", False, "expired", request.remote_addr)
        send_incorrect_webhook(projects[0], code)
        return jsonify({"success": False, "reason": "invalid_code"})

    note_str = ""
    is_owner = db_get("projects", {"id": f"eq.{project_id}", "owner_id": f"eq.{rec['user_id']}", "select": "id"})
    if not is_owner:
        still_tester = db_get("project_testers", {
            "project_id": f"eq.{project_id}",
            "tester_uuid": f"eq.{rec['tester_uuid']}",
            "select": "id,note"
        })
        if not still_tester:
            log_audit(project_id, rec["user_id"], rec["tester_uuid"], "validate_code", False, "access_revoked", request.remote_addr)
            send_incorrect_webhook(projects[0], code)
            return jsonify({"success": False, "reason": "invalid_code"})
        
        note = still_tester[0].get("note")
        if note:
            note_str = f' "{note}"'
    else:
        note_str = ' *(Owner)*'

    db_patch("launch_codes", {"id": f"eq.{rec['id']}"}, {"used_at": datetime.now(timezone.utc).isoformat()})
    log_audit(project_id, rec["user_id"], rec["tester_uuid"], "validate_code", True, None, request.remote_addr)
    
    webhook_url = projects[0].get("webhook_url")
    if webhook_url and projects[0].get("log_play"):
        webhook_color = projects[0].get("webhook_color") or "#3b82f6"
        try:
            color_int = int(webhook_color.lstrip('#'), 16)
        except Exception:
            color_int = 3900150
            
        embed = {
            "title": f"Playing mod: {project_name}",
            "color": color_int,
            "description": f"**Project:** {project_name}\n**User:** `{rec['tester_uuid']}`{note_str}\n**Code used:** `{code}`\n**Accessed on:** <t:{int(datetime.now().timestamp())}:R>",
            "footer": {
                "text": f"jarshield audit logs - https://manage.jarshield.link/ • made by 4xnico"
            }
        }
        try:
            http.post(webhook_url, json={"embeds": [embed]}, timeout=2)
        except Exception:
            pass

    return jsonify({"success": True, "tester_uuid": rec["tester_uuid"], "decryption_key": decryption_key})

@app.route("/api/projects", methods=["GET"])
@require_auth
def list_projects():
    rows = db_get("projects", {"owner_id": f"eq.{request.user_id}", "select": "*"})
    return jsonify(rows)

@app.route("/api/projects", methods=["POST"])
@require_auth
def create_project():
    data = request.get_json() or {}
    name = data.get("name", "").strip().lower()
    if not name:
        return jsonify({"error": "invalid_name"}), 400

    existing = db_get("projects", {"owner_id": f"eq.{request.user_id}", "select": "id"})
    if len(existing) >= 5:
        return jsonify({"error": "max_projects_reached"}), 400

    try:
        row = db_post("projects", {"name": name, "owner_id": request.user_id})
        return jsonify(row[0] if isinstance(row, list) else row)
    except Exception:
        return jsonify({"error": "name_taken_or_invalid"}), 400

@app.route("/api/projects/<project_id>/testers", methods=["GET"])
@require_auth
def get_testers(project_id):
    owns = db_get("projects", {"id": f"eq.{project_id}", "owner_id": f"eq.{request.user_id}", "select": "id"})
    if not owns:
        return jsonify({"error": "unauthorized"}), 403
    rows = db_get("project_testers", {"project_id": f"eq.{project_id}", "select": "*"})
    return jsonify(rows)

@app.route("/api/projects/<project_id>/key", methods=["PUT"])
@require_auth
def update_project_key(project_id):
    owns = db_get("projects", {"id": f"eq.{project_id}", "owner_id": f"eq.{request.user_id}", "select": "id"})
    if not owns:
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json() or {}
    key = data.get("decryption_key", "").strip()
    
    db_patch("projects", {"id": f"eq.{project_id}"}, {"decryption_key": key or None})
    return jsonify({"success": True})

@app.route("/api/projects/<project_id>/webhook", methods=["PUT"])
@require_auth
def update_project_webhook(project_id):
    owns = db_get("projects", {"id": f"eq.{project_id}", "owner_id": f"eq.{request.user_id}", "select": "id"})
    if not owns:
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json() or {}
    webhook_url = data.get("webhook_url", "").strip()
    webhook_color = data.get("webhook_color", "#3b82f6").strip()
    log_generate = bool(data.get("log_generate", False))
    log_play = bool(data.get("log_play", False))
    log_incorrect = bool(data.get("log_incorrect", False))
    
    db_patch("projects", {"id": f"eq.{project_id}"}, {
        "webhook_url": webhook_url or None, 
        "webhook_color": webhook_color,
        "log_generate": log_generate,
        "log_play": log_play,
        "log_incorrect": log_incorrect
    })
    return jsonify({"success": True})

@app.route("/api/projects/by-name/<project_name>/key", methods=["PUT"])
@require_auth
def update_project_key_by_name(project_name):
    owns = db_get("projects", {"name": f"eq.{project_name.lower()}", "owner_id": f"eq.{request.user_id}", "select": "id"})
    if not owns:
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json() or {}
    key = data.get("decryption_key", "").strip()
    
    db_patch("projects", {"id": f"eq.{owns[0]['id']}"}, {"decryption_key": key or None})
    return jsonify({"success": True})

@app.route("/api/projects/<project_id>/testers", methods=["POST"])
@require_auth
def add_tester(project_id):
    owns = db_get("projects", {"id": f"eq.{project_id}", "owner_id": f"eq.{request.user_id}", "select": "id"})
    if not owns:
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json() or {}
    tester_uuid = data.get("tester_uuid", "").strip()
    note = data.get("note", "").strip() or None
    if not tester_uuid:
        return jsonify({"error": "invalid_uuid"}), 400

    try:
        row = db_post("project_testers", {"project_id": project_id, "tester_uuid": tester_uuid, "note": note})
        log_audit(project_id, request.user_id, tester_uuid, "add_tester", True, None, request.remote_addr)
        return jsonify(row[0] if isinstance(row, list) else row)
    except Exception:
        return jsonify({"error": "already_exists_or_invalid"}), 400

@app.route("/api/projects/<project_id>/testers/<tester_uuid>", methods=["DELETE"])
@require_auth
def remove_tester(project_id, tester_uuid):
    owns = db_get("projects", {"id": f"eq.{project_id}", "owner_id": f"eq.{request.user_id}", "select": "id"})
    if not owns:
        return jsonify({"error": "unauthorized"}), 403

    db_delete("project_testers", {"project_id": f"eq.{project_id}", "tester_uuid": f"eq.{tester_uuid}"})
    log_audit(project_id, request.user_id, tester_uuid, "remove_tester", True, None, request.remote_addr)
    return jsonify({"success": True})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

