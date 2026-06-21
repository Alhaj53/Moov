from flask import Flask, request, jsonify, render_template
import httpx
import re
import secrets
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("signin.html")

# =========================
# إعدادات API
# =========================
signup_url = "http://ec2-18-210-103-52.compute-1.amazonaws.com/mymoovbemobile/auth/signupByPhone"
signin_url = "http://ec2-18-210-103-52.compute-1.amazonaws.com/mymoovbemobile/auth/signInByPhone"
firebase_url = "https://moov-24948-default-rtdb.firebaseio.com/users"

headers = {
    "User-Agent": "Dart/3.5 (dart:io)",
    "Accept": "application/json; charset=UTF-8",
    "Content-Type": "application/json",
    "lang": "fr"
}

# =========================
# أدوات مساعدة
# =========================
def validate_phone(phone):
    return re.fullmatch(r"4\d{7}", phone) is not None

def validate_password(password):
    return re.fullmatch(r"\d{4}", password) is not None

def generate_token(phone):
    return f"{phone}_{secrets.token_hex(32)}"

def created_at():
    return datetime.utcnow().isoformat()

async def fetch_json(client, method, url, **kwargs):
    try:
        r = await client.request(method, url, timeout=10, **kwargs)
        return r.status_code, r.json() if r.text else {}
    except Exception as e:
        return 500, {"error": str(e)}

# =========================
# إنشاء حساب (إرسال OTP)
# =========================
@app.route("/api/signup/start", methods=["POST"])
async def signup_start():
    data = request.json or {}

    phone = data.get("phone")
    password = data.get("password")

    if not phone or not password:
        return jsonify({
            "status": "error",
            "message": "البيانات ناقصة"
        }), 400

    if not validate_phone(phone):
        return jsonify({
            "status": "error",
            "message": "رقم الهاتف غير صالح"
        }), 400

    if not validate_password(password):
        return jsonify({
            "status": "error",
            "message": "كلمة المرور غير صحيحة"
        }), 400

    # التحقق من Firebase (منع التكرار)
    async with httpx.AsyncClient(verify=True) as client:
        status, existing = await fetch_json(
            client,
            "GET",
            f"{firebase_url}/{phone}.json"
        )

    if existing:
        return jsonify({
            "status": "error",
            "message": "هذا الرقم مسجل مسبقاً يرجى تسجيل الدخول"
        }), 409

    payload = {
        "phone": phone
    }

    async with httpx.AsyncClient(verify=True) as client:
        status, resp = await fetch_json(
            client,
            "POST",
            signup_url,
            json=payload,
            headers=headers
        )

    if status != 200:
        return jsonify({
            "status": "error",
            "message": "فشل إرسال OTP",
            "details": resp
        }), 500

    return jsonify({
        "status": "success",
        "message": "ادخل رمز OTP الذي وصلك عبر SMS"
    })

# =========================
# التحقق وإنشاء الحساب النهائي
# =========================
@app.route("/api/signup/verify", methods=["POST"])
async def signup_verify():
    data = request.json or {}

    phone = data.get("phone")
    password = data.get("password")
    otp = data.get("otp")

    if not all([phone, password, otp]):
        return jsonify({
            "status": "error",
            "message": "بيانات ناقصة"
        }), 400

    payload = {
        "phoneNo": phone,
        "otp": otp
    }
    
    async with httpx.AsyncClient(verify=True) as client:
        status, resp = await fetch_json(
            client,
            "POST",
            signin_url,
            json=payload,
            headers=headers
        )

    if status != 200:
        return jsonify({
            "status": "error",
            "message": "فشل التحقق من OTP",
            "details": resp
        }), 401

    # استخراج الاسم من nomPrenom
    username = "مستخدم"

    if isinstance(resp, dict):
        username = resp.get("nomPrenom", "مجهول")

        parts = username.split()
        if len(parts) >= 2:
            username = " ".join(reversed(parts))

    # إنشاء التوكن
    token = generate_token(phone)

    # وقت إنشاء الحساب
    account_created_at = created_at()

    firebase_data = {
        "phone": phone,
        "username": username,
        "password": password,
        "points": 2,
        "token": token,
        "created_at": account_created_at
    }

    # حفظ البيانات في Firebase
    async with httpx.AsyncClient(verify=True) as client:
        await fetch_json(
            client,
            "PUT",
            f"{firebase_url}/{phone}.json",
            json=firebase_data
        )

    return jsonify({
        "status": "success",
        "message": f"تم إنشاء الحساب بنجاح، مرحباً {username}"

    })
@app.route("/api/login", methods=["POST"])
async def login():

    data = request.json or {}

    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", "")).strip()

    if not phone:
        return jsonify({
            "status": "error",
            "message": "يرجى إدخال رقم الهاتف"
        }), 400

    if not password:
        return jsonify({
            "status": "error",
            "message": "يرجى إدخال كلمة المرور"
        }), 400

    if not validate_phone(phone):
        return jsonify({
            "status": "error",
            "message": "رقم الهاتف غير صالح"
        }), 400

    if not validate_password(password):
        return jsonify({
            "status": "error",
            "message": "كلمة المرور غير صالحة"
        }), 400

    async with httpx.AsyncClient(verify=True) as client:

        response = await client.get(
            f"{firebase_url}/{phone}.json"
        )

    if response.status_code != 200:
        return jsonify({
            "status": "error",
            "message": "تعذر الاتصال بقاعدة البيانات"
        }), 500

    user = response.json()

    if not user:
        return jsonify({
            "status": "error",
            "message": "رقم الهاتف غير مسجل"
        }), 404

    if str(user.get("password", "")) != password:
        return jsonify({
            "status": "error",
            "message": "كلمة المرور غير صحيحة"
        }), 401

    return jsonify({
        "status": "success",
        "message": f"مرحباً {user.get('username', 'مستخدم')}",
        "username": user.get("username"),
        "token": user.get("token")
    }), 200
@app.route("/api/token-login", methods=["POST"])
async def token_login():

    data = request.json or {}
    token = str(data.get("token", "")).strip()

    if not token:
        return jsonify({
            "status": "error",
            "message": "التوكن مفقود"
        }), 400

    try:
        phone = token.split("_")[0]

        if not validate_phone(phone):
            return jsonify({
                "status": "error",
                "message": "توكن غير صالح"
            }), 401

    except Exception:
        return jsonify({
            "status": "error",
            "message": "توكن غير صالح"
        }), 401

    try:

        async with httpx.AsyncClient(verify=True) as client:

            response = await client.get(
                f"{firebase_url}/{phone}.json"
            )

    except Exception:

        return jsonify({
            "status": "error",
            "message": "تعذر الاتصال بقاعدة البيانات"
        }), 500

    if response.status_code != 200:
        return jsonify({
            "status": "error",
            "message": "فشل جلب بيانات المستخدم"
        }), 500

    user = response.json()

    if not user:
        return jsonify({
            "status": "error",
            "message": "المستخدم غير موجود"
        }), 404

    if user.get("token") != token:
        return jsonify({
            "status": "error",
            "message": "التوكن غير صحيح"
        }), 401

    return jsonify({
        "status": "success",
        "message": f"مرحباً {user.get('username', 'مستخدم')}",
        "user": user
    }), 200    
# =========================
# تشغيل السيرفر
# =========================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
