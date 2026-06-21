from flask import Flask, request, jsonify, render_template
import httpx
import re

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("signin.html")

# =========================
# إعدادات Firebase
# =========================
firebase_url = "https://moov-24948-default-rtdb.firebaseio.com/users"

# =========================
# التحقق من البيانات
# =========================
def validate_phone(phone):
    return re.fullmatch(r"4\d{7}", phone) is not None

def validate_password(password):
    return re.fullmatch(r"\d{4}", password) is not None

# =========================
# تسجيل الدخول
# =========================
@app.route("/api/login", methods=["POST"])
async def login():

    if not request.is_json:
        return jsonify({
            "status": "error",
            "message": "يجب إرسال البيانات بصيغة JSON"
        }), 400

    data = request.get_json(silent=True) or {}

    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", "")).strip()

    # التحقق من وجود البيانات
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

    # التحقق من صحة رقم الهاتف
    if not validate_phone(phone):
        return jsonify({
            "status": "error",
            "message": "رقم الهاتف غير صالح"
        }), 400

    # التحقق من صحة كلمة المرور
    if not validate_password(password):
        return jsonify({
            "status": "error",
            "message": "كلمة المرور غير صالحة"
        }), 400

    try:

        async with httpx.AsyncClient(
            verify=True,
            timeout=10,
            follow_redirects=False
        ) as client:

            response = await client.get(
                f"{firebase_url}/{phone}.json"
            )

            if response.status_code != 200:
                return jsonify({
                    "status": "error",
                    "message": "تعذر الاتصال بقاعدة البيانات"
                }), 500

            user = response.json()

    except Exception:
        return jsonify({
            "status": "error",
            "message": "حدث خطأ أثناء الاتصال بالخادم"
        }), 500

    # الحساب غير موجود
    if not user:
        return jsonify({
            "status": "error",
            "message": "رقم الهاتف غير مسجل"
        }), 404

    # التحقق من كلمة المرور
    stored_password = str(user.get("password", ""))

    if stored_password != password:
        return jsonify({
            "status": "error",
            "message": "كلمة المرور غير صحيحة"
        }), 401

    username = user.get("username", "مستخدم")
    token = user.get("token")

    return jsonify({
        "status": "success",
        "message": f"مرحباً {username}",
        "username": username,
        "token": token
    }), 200

# =========================
# تشغيل السيرفر
# =========================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
          )
