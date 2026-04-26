from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import hashlib
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Bật CORS cho tất cả

HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.32 (iPhone9,1;ios - 15.8.7;vi-US;US;app v1.123.1 2019120273)",
    "Accept": "*/*",
    "Accept-Language": "vi-VN,vi;q=0.9",
    "Content-Type": "application/x-www-form-urlencoded",
    "Connection": "keep-alive"
}

GARENA_API = "https://100067.connect.garena.com"


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "name": "Garena Mail API",
        "version": "2.0",
        "status": "running",
        "endpoints": {
            "GET /checkmail": "?access_token=xxx - Kiểm tra email/SĐT",
            "POST /sendotp": "?access_token=xxx&email=xxx - Gửi OTP",
            "POST /verifyotp": "?access_token=xxx&email=xxx&otp=xxx - Xác thực OTP",
            "POST /bindmail": "?access_token=xxx&email=xxx&password=xxx&verifier_token=xxx - Liên kết email",
            "POST /cancelreq": "?access_token=xxx - Hủy yêu cầu",
            "GET /inspect": "?access_token=xxx - Kiểm tra token",
            "POST /logout": "?access_token=xxx - Đăng xuất"
        }
    })


@app.route("/checkmail", methods=["GET", "OPTIONS"])
def check_mail():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    
    access_token = request.args.get("access_token")
    
    if not access_token:
        return jsonify({"success": False, "error": "Thiếu access_token"}), 400
    
    try:
        resp = requests.get(
            f"{GARENA_API}/game/account_security/bind:get_bind_info",
            params={"app_id": "100067", "access_token": access_token},
            headers=HEADERS,
            timeout=15
        )
        
        if resp.status_code != 200:
            return jsonify({"success": False, "error": f"Garena API error: {resp.status_code}"})
        
        data = resp.json()
        
        return jsonify({
            "success": data.get("result") == 0,
            "data": {
                "email": data.get("email") or None,
                "mobile": data.get("mobile") or None,
                "email_to_be": data.get("email_to_be") or None,
                "mobile_to_be": data.get("mobile_to_be") or None,
                "request_exec_countdown": data.get("request_exec_countdown", 0),
                "has_email": bool(data.get("email")),
                "has_mobile": bool(data.get("mobile")),
                "has_pending": bool(data.get("email_to_be") or data.get("mobile_to_be"))
            },
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/sendotp", methods=["POST", "OPTIONS"])
def send_otp():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    
    access_token = request.args.get("access_token") or request.form.get("access_token")
    email = request.args.get("email") or request.form.get("email")
    
    if not access_token or not email:
        return jsonify({"success": False, "error": "Thiếu access_token hoặc email"}), 400
    
    data = {
        "email": email,
        "locale": "vi_VN",
        "region": "VN",
        "app_id": "100067",
        "access_token": access_token
    }
    
    try:
        resp = requests.post(
            f"{GARENA_API}/game/account_security/bind:send_otp",
            data=data,
            headers=HEADERS,
            timeout=15
        )
        result = resp.json()
        
        return jsonify({
            "success": result.get("result") == 0,
            "message": "OTP đã gửi" if result.get("result") == 0 else result.get("error_msg", "Lỗi"),
            "result": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/verifyotp", methods=["POST", "OPTIONS"])
def verify_otp():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    
    access_token = request.args.get("access_token") or request.form.get("access_token")
    email = request.args.get("email") or request.form.get("email")
    otp = request.args.get("otp") or request.form.get("otp")
    
    if not all([access_token, email, otp]):
        return jsonify({"success": False, "error": "Thiếu access_token, email hoặc otp"}), 400
    
    data = {
        "email": email,
        "app_id": "100067",
        "access_token": access_token,
        "otp": otp
    }
    
    try:
        resp = requests.post(
            f"{GARENA_API}/game/account_security/bind:verify_otp",
            data=data,
            headers=HEADERS,
            timeout=15
        )
        result = resp.json()
        
        return jsonify({
            "success": result.get("result") == 0,
            "verifier_token": result.get("verifier_token") if result.get("result") == 0 else None,
            "message": "Xác thực OTP thành công" if result.get("result") == 0 else result.get("error_msg", "OTP không đúng"),
            "result": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/bindmail", methods=["POST", "OPTIONS"])
def bind_mail():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    
    access_token = request.args.get("access_token") or request.form.get("access_token")
    email = request.args.get("email") or request.form.get("email")
    password = request.args.get("password") or request.form.get("password")
    verifier_token = request.args.get("verifier_token") or request.form.get("verifier_token")
    
    if not all([access_token, email, password, verifier_token]):
        return jsonify({"success": False, "error": "Thiếu tham số"}), 400
    
    hashed_pw = hashlib.sha256(password.encode("utf-8")).hexdigest().upper()
    
    data = {
        "email": email,
        "secondary_password": hashed_pw,
        "app_id": "100067",
        "verifier_token": verifier_token,
        "access_token": access_token
    }
    
    try:
        resp = requests.post(
            f"{GARENA_API}/game/account_security/bind:create_bind_request",
            data=data,
            headers=HEADERS,
            timeout=15
        )
        result = resp.json()
        
        return jsonify({
            "success": result.get("result") == 0,
            "message": "Liên kết email thành công" if result.get("result") == 0 else result.get("error_msg", "Lỗi"),
            "result": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/cancelreq", methods=["POST", "OPTIONS"])
def cancel_request():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    
    access_token = request.args.get("access_token") or request.form.get("access_token")
    
    if not access_token:
        return jsonify({"success": False, "error": "Thiếu access_token"}), 400
    
    data = {
        "app_id": "100067",
        "access_token": access_token
    }
    
    try:
        resp = requests.post(
            f"{GARENA_API}/game/account_security/bind:cancel_request",
            data=data,
            headers=HEADERS,
            timeout=15
        )
        result = resp.json()
        
        return jsonify({
            "success": result.get("result") == 0,
            "message": "Đã hủy yêu cầu" if result.get("result") == 0 else result.get("error_msg", "Lỗi"),
            "result": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/inspect", methods=["GET", "OPTIONS"])
def inspect_token():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    
    access_token = request.args.get("access_token")
    
    if not access_token:
        return jsonify({"success": False, "error": "Thiếu access_token"}), 400
    
    try:
        resp = requests.get(
            f"{GARENA_API}/oauth/token/inspect",
            params={"token": access_token},
            headers=HEADERS,
            timeout=10
        )
        data = resp.json()
        
        if "error" not in data and data.get("open_id"):
            return jsonify({
                "success": True,
                "open_id": data.get("open_id"),
                "platform": data.get("platform"),
                "expires_in": data.get("expires_in")
            })
        else:
            return jsonify({"success": False, "error": "Token không hợp lệ"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/logout", methods=["POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
    
    access_token = request.args.get("access_token") or request.form.get("access_token")
    
    if not access_token:
        return jsonify({"success": False, "error": "Thiếu access_token"}), 400
    
    try:
        resp = requests.get(
            f"{GARENA_API}/oauth/logout",
            params={"access_token": access_token},
            headers=HEADERS,
            timeout=10
        )
        result = resp.json()
        
        return jsonify({
            "success": result.get("result") == 0,
            "message": "Đăng xuất thành công" if result.get("result") == 0 else "Đăng xuất thất bại"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


def _build_cors_preflight_response():
    response = jsonify({"message": "CORS preflight"})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    return response


# Vercel handler
app.config['JSON_AS_ASCII'] = False

# For local development
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010, debug=True)
