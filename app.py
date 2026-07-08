import os
import re
import base64
import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import jwt

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin@localhost:3306/passwdmanager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SERVER_SECRET'] = os.environ.get('SERVER_SECRET', b'super_secret_32_byte_key_must_be_32_bytes_long!')[:32].ljust(32, b'0')

db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    master_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(255))
    username_enc = db.Column(db.Text, nullable=False)
    password_enc = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- Robust Cryptography Layer ---
def derive_vault_key(master_password, salt_b64):
    """OWASP Recommended 600,000 iterations for PBKDF2-HMAC-SHA256"""
    salt = base64.b64decode(salt_b64)
    return PBKDF2(master_password, salt, dkLen=32, count=600000)

def encrypt_data(plain_text, key):
    """Standard AES-256-GCM Encryption with random 12-byte Nonce"""
    if not plain_text: return ""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    # Return payload: nonce (16 bytes) + tag (16 bytes) + ciphertext
    payload = cipher.nonce + tag + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def decrypt_data(enc_text, key):
    """Standard AES-256-GCM Decryption"""
    if not enc_text: return ""
    try:
        raw_data = base64.b64decode(enc_text)
        nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except BaseException:
        return "DECRYPTION_ERROR"

# --- Security Middleware ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({'error': 'Missing or invalid token'}), 401
        try:
            token = auth_header.split(" ")[1]
            data = jwt.decode(token, app.config['SERVER_SECRET'], algorithms=["HS256"])
            
            # Decrypt the vault key from the token payload
            enc_vault_key = data['enc_vault_key']
            vault_key_bytes = decrypt_data(enc_vault_key, app.config['SERVER_SECRET']).encode('latin1')
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Session expired. Please log in again.'}), 401
        except Exception as e:
            return jsonify({'error': 'Token validation failed'}), 401
            
        return f(data['user_id'], vault_key_bytes, *args, **kwargs)
    return decorated

# --- Routes ---
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email', '').strip().lower()
    master_password = data.get('master_password', '')

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email format"}), 400
    if len(master_password) < 12:
        return jsonify({"error": "Master password must be at least 12 characters"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409

    salt = base64.b64encode(get_random_bytes(16)).decode('utf-8')
    hashed_pw = generate_password_hash(master_password, method='scrypt')
    
    new_user = User(email=email, master_hash=hashed_pw, salt=salt)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registration successful"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').strip().lower()
    master_password = data.get('master_password', '')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.master_hash, master_password):
        # Derive the key, then encrypt it with the Server Secret to safely store in JWT
        vault_key = derive_vault_key(master_password, user.salt)
        enc_vault_key = encrypt_data(vault_key.decode('latin1'), app.config['SERVER_SECRET'])

        token = jwt.encode({
            'user_id': user.id,
            'enc_vault_key': enc_vault_key,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
        }, app.config['SERVER_SECRET'], algorithm="HS256")
        
        return jsonify({'token': token, 'email': user.email})
        
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/passwords', methods=['GET', 'POST'])
@token_required
def manage_passwords(current_user_id, vault_key):
    if request.method == 'POST':
        data = request.json
        if not data.get('name') or not data.get('password'):
            return jsonify({"error": "Name and Password are required"}), 400

        new_entry = PasswordEntry(
            user_id=current_user_id,
            name=data['name'],
            website=data.get('website', ''),
            category=data.get('category', 'Other'),
            username_enc=encrypt_data(data.get('username', ''), vault_key),
            password_enc=encrypt_data(data['password'], vault_key)
        )
        db.session.add(new_entry)
        db.session.commit()
        return jsonify({"message": "Saved securely", "id": new_entry.id}), 201

    if request.method == 'GET':
        entries = PasswordEntry.query.filter_by(user_id=current_user_id).order_by(PasswordEntry.created_at.desc()).all()
        result = []
        for e in entries:
            result.append({
                "id": e.id,
                "name": e.name,
                "website": e.website,
                "category": e.category,
                "username": decrypt_data(e.username_enc, vault_key),
                "password": decrypt_data(e.password_enc, vault_key)
            })
        return jsonify(result), 200

@app.route('/api/passwords/<int:entry_id>', methods=['DELETE'])
@token_required
def delete_password(current_user_id, vault_key, entry_id):
    # Ensure the entry exists and belongs to the authenticated user
    entry = PasswordEntry.query.filter_by(id=entry_id, user_id=current_user_id).first()
    
    if not entry:
        return jsonify({"error": "Credential node not found or unauthorized"}), 404

    db.session.delete(entry)
    db.session.commit()
    return jsonify({"message": "Credential deleted safely from vault"}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000, threaded=True)