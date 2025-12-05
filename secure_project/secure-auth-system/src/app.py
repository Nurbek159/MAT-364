# src/app.py
from flask import Flask, request, jsonify, redirect, url_for, render_template, make_response
from models import db, User
from crypto.jwt_helper import create_token, verify_signature, decode_token_unsafe, PUB_KEY
import os
import pyotp
import qrcode
import io
import base64
import datetime

# Указываем Flask где искать папки static и templates
app = Flask(__name__, template_folder='templates', static_folder='static')

# Настройки
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

db.init_app(app)

# --- МАРШРУТЫ ---

@app.route('/')
def home():
    return render_template('index.html')

# 1. РЕГИСТРАЦИЯ
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            return "User already exists", 400

        totp_secret = pyotp.random_base32()
        new_user = User(username=username, totp_secret=totp_secret)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Генерация QR
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Lumina Secure")
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf)
        img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        return render_template('register_qr.html', img_data=img_b64, secret=totp_secret, username=username)

    return render_template('register.html')

@app.route('/register/verify_setup', methods=['GET', 'POST'])
def register_verify():
    username = request.args.get('username') or request.form.get('username')
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        user = User.query.filter_by(username=username).first()
        totp = pyotp.TOTP(user.totp_secret)
        
        if totp.verify(otp_code):
            # После успеха отправляем на логин, но можно показать success page
            return redirect(url_for('login_step1'))
            
        return "Wrong code! Please try again." # Лучше обработать ошибку красивее, но пока так

    return render_template('verify_setup.html', username=username)

# 2. ЛОГИН ШАГ 1
@app.route('/login', methods=['GET', 'POST'])
def login_step1():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            temp_token = create_token(user.id, user.username, duration=600, scope="partial")
            resp = make_response(redirect(url_for('login_step2_page')))
            resp.set_cookie('temp_token', temp_token, max_age=600, httponly=True)
            return resp
            
        return "Invalid credentials", 401 # Можно сделать Flash message

    return render_template('login_step1.html')

@app.route('/login/2fa', methods=['GET'])
def login_step2_page():
    return render_template('login_step2.html')

# 3. ЛОГИН ШАГ 2
@app.route('/login/2fa', methods=['POST'])
def login_step2_post():
    temp_token = request.cookies.get('temp_token')
    otp_code = request.form.get('otp_code')
    
    if not temp_token:
        return redirect(url_for('login_step1'))

    try:
        parts = temp_token.split('.')
        if not verify_signature(f"{parts[0]}.{parts[1]}", parts[2], PUB_KEY):
             return "Security Error", 401
             
        user_data = decode_token_unsafe(temp_token)
        user = User.query.get(user_data['sub'])
        
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_code):
            final_token = create_token(user.id, user.username, duration=604800, scope="full")
            
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('access_token', final_token, max_age=604800, httponly=True)
            resp.set_cookie('temp_token', '', expires=0)
            return resp
        else:
            return "Invalid Code", 401
    except Exception as e:
        return f"Error: {e}", 400

# 4. DASHBOARD
@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('access_token')
    if not token: token = request.args.get('token')

    if not token: return redirect(url_for('login_step1'))
    
    try:
        parts = token.split('.')
        if verify_signature(f"{parts[0]}.{parts[1]}", parts[2], PUB_KEY):
            data = decode_token_unsafe(token)
            if data.get('scope') != 'full':
                return "Access Denied", 403
            
            # Красивый вывод даты
            exp_time = datetime.datetime.fromtimestamp(data['exp']).strftime('%Y-%m-%d %H:%M:%S')
                
            return render_template('dashboard.html', user_name=data['name'], expiration=exp_time)
        else:
            return "FAKE TOKEN DETECTED", 401
    except Exception as e:
        return f"Error: {e}", 400

@app.route('/logout')
def logout():
    resp = make_response(redirect('/login'))
    resp.set_cookie('access_token', '', expires=0)
    resp.set_cookie('temp_token', '', expires=0)
    return resp

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)