# src/crypto/jwt_helper.py
import base64
import json
import hashlib
import time
import os
from .rsa_manual import generate_keypair

KEYS_FILE = "rsa_keys.json"

def load_or_generate_keys():
    if os.path.exists(KEYS_FILE):
        print("Loading existing RSA keys from file...")
        try:
            with open(KEYS_FILE, "r") as f:
                data = json.load(f)
                return tuple(data["public"]), tuple(data["private"])
        except:
            print("Error loading keys. Generating new ones.")

    print("Generating NEW RSA keys... This may take a moment.")
    pub, priv = generate_keypair()
    
    with open(KEYS_FILE, "w") as f:
        json.dump({"public": pub, "private": priv}, f)
    print("Keys saved to rsa_keys.json")
    return pub, priv

# Загружаем ключи
PUB_KEY, PRIV_KEY = load_or_generate_keys()

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def sign_data(data_str, private_key):
    d, n = private_key
    
    # 1. Считаем SHA-256
    hash_obj = hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    hash_int = int(hash_obj, 16)
    
    # !!! ВАЖНОЕ ИСПРАВЛЕНИЕ !!!
    # Чтобы хеш поместился в наш RSA ключ, берем остаток от деления на n
    # Это гарантирует, что message < n
    msg_to_sign = hash_int % n
    
    # 2. Подписываем: s = m^d mod n
    signature_int = pow(msg_to_sign, d, n)
    
    return str(signature_int)

def verify_signature(data_str, signature_str, public_key):
    e, n = public_key
    try:
        signature_int = int(signature_str)
    except ValueError:
        return False
    
    # 1. Расшифровываем подпись: m' = s^e mod n
    decrypted_hash_mod_n = pow(signature_int, e, n)
    
    # 2. Считаем реальный хеш данных
    real_hash_obj = hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    real_hash_int = int(real_hash_obj, 16)
    
    # !!! ВАЖНОЕ ИСПРАВЛЕНИЕ !!!
    # Приводим реальный хеш к тому же виду (mod n)
    expected_val = real_hash_int % n
    
    # Для отладки в консоли
    if decrypted_hash_mod_n != expected_val:
        print(f"DEBUG FAIL: SigDecoded={decrypted_hash_mod_n} vs RealHash={expected_val}")
        
    return decrypted_hash_mod_n == expected_val

# src/crypto/jwt_helper.py (Только обновленная функция, остальное оставьте как было)

def create_token(user_id, username, duration=3600, scope="full"):
    """
    duration: время жизни в секундах
    scope: 'partial' (только пароль) или 'full' (пароль + 2FA)
    """
    header = {"alg": "CustomRSA", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "name": username,
        "scope": scope,  # Пометка: полный доступ или частичный
        "iat": int(time.time()),
        "exp": int(time.time()) + duration 
    }
    
    header_b64 = base64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = base64url_encode(json.dumps(payload).encode('utf-8'))
    
    data_to_sign = f"{header_b64}.{payload_b64}"
    signature = sign_data(data_to_sign, PRIV_KEY)
    
    return f"{data_to_sign}.{signature}"

# Вспомогательная функция для декодирования без проверки подписи (чтобы достать данные)
def decode_token_unsafe(token):
    try:
        parts = token.split('.')
        payload_b64 = parts[1]
        # Добавляем padding если нужно
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_data = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_data)
    except:
        return None