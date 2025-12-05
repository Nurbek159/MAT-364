# src/crypto/rsa_manual.py
import random
import math

def is_prime(number):
    """Простейшая проверка на простоту (для учебных целей)."""
    if number < 2:
        return False
    for i in range(2, int(math.sqrt(number)) + 1):
        if number % i == 0:
            return False
    return True

def generate_prime(min_val, max_val):
    """Генерирует простое число в заданном диапазоне."""
    while True:
        num = random.randint(min_val, max_val)
        if is_prime(num):
            return num

def gcd(a, b):
    """Алгоритм Евклида для поиска НОД."""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Расширенный алгоритм Евклида для поиска d."""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = extended_gcd(b % a, a)
            return g, x - (b // a) * y, y

    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % phi

def generate_keypair(keysize=1024):
    """
    Генерирует публичный и приватный ключи.
    Возвращает ((e, n), (d, n))
    """
    # 1. Генерируем два простых числа p и q
    # Для учебного примера берем небольшой диапазон, чтобы работало быстро.
    # В реальной жизни числа должны быть огромными.
    # Увеличим числа, чтобы n было побольше (хотя бы 4-5 знаков)
    p = generate_prime(1000, 5000) 
    q = generate_prime(1000, 5000)
    
    # Убедимся, что p != q
    while p == q:
        q = generate_prime(100, 300)

    # 2. Вычисляем n и функцию Эйлера phi
    n = p * q
    phi = (p - 1) * (q - 1)

    # 3. Выбираем e (обычно 65537, но можно взять случайное взаимно простое с phi)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # 4. Вычисляем d (секретная экспонента)
    d = mod_inverse(e, phi)

    # Возвращаем кортеж: ((public_key), (private_key))
    return ((e, n), (d, n))

# Тест модуля (запустите файл напрямую, чтобы проверить)
if __name__ == "__main__":
    print("Generating keys...")
    public, private = generate_keypair()
    print(f"Public Key: {public}")
    print(f"Private Key: {private}")
    
    # Простая проверка шифрования числа
    msg = 42
    encrypted = (msg ** public[0]) % public[1]
    decrypted = (encrypted ** private[0]) % private[1]
    print(f"Original: {msg}, Encrypted: {encrypted}, Decrypted: {decrypted}")