# src/models.py
from flask_sqlalchemy import SQLAlchemy
import bcrypt

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False) # Храним только хеш!
    totp_secret = db.Column(db.String(32), nullable=True)     # Секрет для 2FA

    def set_password(self, password):
        """Хеширование пароля с солью (bcrypt)"""
        # encode преобразует строку в байты, hashpw делает магию
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        """Проверка пароля"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))