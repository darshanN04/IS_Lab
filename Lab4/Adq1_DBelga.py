import os
import sqlite3
import json
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from loguru import logger

# ----------------------------- Configuration -----------------------------

DATABASE = 'drm_system.db'
MASTER_KEY_FILE = 'master_private_key.pem'
MASTER_PUBLIC_KEY_FILE = 'master_public_key.pem'
KEY_SIZE = 2048  # Configurable key size
KEY_RENEWAL_INTERVAL = 24 * 30 * 24 * 60 * 60  # 24 months in seconds

# Initialize Flask app
app = Flask(__name__)

# Configure Logger
logger.add("drm_audit.log", rotation="1 MB")


# ----------------------------- Database Setup -----------------------------

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT 0
        )
    ''')

    # Content Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS content (
            content_id INTEGER PRIMARY KEY AUTOINCREMENT,
            creator_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            encrypted_content BLOB NOT NULL,
            upload_date TIMESTAMP NOT NULL,
            FOREIGN KEY (creator_id) REFERENCES users(user_id)
        )
    ''')

    # Access Control Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_control (
            access_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content_id INTEGER NOT NULL,
            access_granted_at TIMESTAMP NOT NULL,
            access_expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id),
            FOREIGN KEY (content_id) REFERENCES content(content_id)
        )
    ''')

    # Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')

    conn.commit()
    conn.close()


# ----------------------------- Key Management -----------------------------

def generate_master_keys(key_size=KEY_SIZE):
    key = ElGamal.generate(key_size, get_random_bytes)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save keys to files
    with open(MASTER_PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key)
    with open(MASTER_PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key)

    logger.info("Master key pair generated and saved.")
    return key


def load_master_keys():
    if not os.path.exists(MASTER_PRIVATE_KEY_FILE) or not os.path.exists(MASTER_PUBLIC_KEY_FILE):
        logger.warning("Master keys not found. Generating new keys.")
        return generate_master_keys()

    with open(MASTER_PRIVATE_KEY_FILE, 'rb') as f:
        private_key = ElGamal.import_key(f.read())
    with open(MASTER_PUBLIC_KEY_FILE, 'rb') as f:
        public_key = ElGamal.import_key(f.read())

    logger.info("Master keys loaded from storage.")
    return private_key, public_key


def revoke_master_key():
    if os.path.exists(MASTER_PRIVATE_KEY_FILE):
        os.remove(MASTER_PRIVATE_KEY_FILE)
    if os.path.exists(MASTER_PUBLIC_KEY_FILE):
        os.remove(MASTER_PUBLIC_KEY_FILE)
    logger.warning("Master keys have been revoked.")


def renew_master_keys():
    while True:
        time.sleep(KEY_RENEWAL_INTERVAL)
        revoke_master_key()
        generate_master_keys()
        logger.info("Master keys have been renewed.")


# Start key renewal in a separate thread
key_renewal_thread = threading.Thread(target=renew_master_keys, daemon=True)
key_renewal_thread.start()


# ----------------------------- Helper Functions -----------------------------

def log_action(user_id, action, details=None):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, user_id, action, details)
        VALUES (?, ?, ?, ?)
    ''', (datetime.utcnow(), user_id, action, details))
    conn.commit()
    conn.close()
    logger.info(f"Action logged: {action}, Details: {details}")


def encrypt_content(public_key, plaintext):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(plaintext)
    return encrypted


def decrypt_content(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted


# ----------------------------- API Endpoints -----------------------------

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    is_admin = data.get('is_admin', False)

    if not username:
        return jsonify({'error': 'Username is required.'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (username, is_admin)
            VALUES (?, ?)
        ''', (username, is_admin))
        conn.commit()
        user_id = cursor.lastrowid
        log_action(user_id, 'register', f'User {username} registered.')
        return jsonify({'message': 'User registered successfully.', 'user_id': user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists.'}), 400
    finally:
        conn.close()


@app.route('/upload_content', methods=['POST'])
def upload_content():
    data = request.form
    user_id = data.get('user_id')
    title = data.get('title')
    file = request.files.get('file')

    if not user_id or not title or not file:
        return jsonify({'error': 'Missing parameters.'}), 400

    # Load master public key
    _, public_key = load_master_keys()

    # Encrypt the content
    plaintext = file.read()
    encrypted_content = encrypt_content(public_key, plaintext)

    # Save to database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO content (creator_id, title, encrypted_content, upload_date)
        VALUES (?, ?, ?, ?)
    ''', (user_id, title, encrypted_content, datetime.utcnow()))
    conn.commit()
    content_id = cursor.lastrowid
    conn.close()

    log_action(user_id, 'upload_content', f'Content "{title}" uploaded with ID {content_id}.')
    return jsonify({'message': 'Content uploaded and encrypted successfully.', 'content_id': content_id}), 201


@app.route('/grant_access', methods=['POST'])
def grant_access():
    data = request.json
    admin_id = data.get('admin_id')
    user_id = data.get('user_id')
    content_id = data.get('content_id')
    duration_days = data.get('duration_days')  # Optional

    # Verify admin privileges
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE user_id = ?', (admin_id,))
    result = cursor.fetchone()
    if not result or not result[0]:
        conn.close()
        return jsonify({'error': 'Unauthorized. Admin privileges required.'}), 403

    access_granted_at = datetime.utcnow()
    access_expires_at = access_granted_at + timedelta(days=duration_days) if duration_days else None

    cursor.execute('''
        INSERT INTO access_control (user_id, content_id, access_granted_at, access_expires_at)
        VALUES (?, ?, ?, ?)
    ''', (user_id, content_id, access_granted_at, access_expires_at))
    conn.commit()
    conn.close()

    log_action(admin_id, 'grant_access', f'Granted access to user {user_id} for content {content_id}.')
    return jsonify({'message': 'Access granted successfully.'}), 200


@app.route('/revoke_access', methods=['POST'])
def revoke_access():
    data = request.json
    admin_id = data.get('admin_id')
    user_id = data.get('user_id')
    content_id = data.get('content_id')

    # Verify admin privileges
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE user_id = ?', (admin_id,))
    result = cursor.fetchone()
    if not result or not result[0]:
        conn.close()
        return jsonify({'error': 'Unauthorized. Admin privileges required.'}), 403

    cursor.execute('''
        DELETE FROM access_control
        WHERE user_id = ? AND content_id = ?
    ''', (user_id, content_id))
    conn.commit()
    conn.close()

    log_action(admin_id, 'revoke_access', f'Revoked access for user {user_id} to content {content_id}.')
    return jsonify({'message': 'Access revoked successfully.'}), 200


@app.route('/download_content/<int:content_id>', methods=['GET'])
def download_content(content_id):
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({'error': 'User ID is required.'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check access rights
    cursor.execute('''
        SELECT access_expires_at FROM access_control
        WHERE user_id = ? AND content_id = ?
    ''', (user_id, content_id))
    access = cursor.fetchone()
    if not access:
        conn.close()
        return jsonify({'error': 'Access denied. No permissions found.'}), 403
    if access[0] and datetime.strptime(access[0], '%Y-%m-%d %H:%M:%S.%f') < datetime.utcnow():
        conn.close()
        return jsonify({'error': 'Access expired.'}), 403

    # Fetch encrypted content
    cursor.execute('''
        SELECT encrypted_content, title FROM content
        WHERE content_id = ?
    ''', (content_id,))
    content = cursor.fetchone()
    conn.close()

    if not content:
        return jsonify({'error': 'Content not found.'}), 404

    encrypted_content, title = content
    encrypted_file = f'encrypted_{title}.bin'

    with open(encrypted_file, 'wb') as f:
        f.write(encrypted_content)

    log_action(user_id, 'download_content', f'User {user_id} downloaded content {content_id}.')
    return send_file(encrypted_file, as_attachment=True, attachment_filename=title + '.bin')


@app.route('/get_master_private_key', methods=['GET'])
def get_master_private_key():
    admin_id = request.args.get('admin_id')

    # Verify admin privileges
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE user_id = ?', (admin_id,))
    result = cursor.fetchone()
    if not result or not result[0]:
        conn.close()
        return jsonify({'error': 'Unauthorized. Admin privileges required.'}), 403

    if not os.path.exists(MASTER_PRIVATE_KEY_FILE):
        conn.close()
        return jsonify({'error': 'Master private key revoked or not available.'}), 403

    with open(MASTER_PRIVATE_KEY_FILE, 'rb') as f:
        private_key = f.read()

    conn.close()
    log_action(admin_id, 'get_master_private_key', 'Master private key distributed.')
    return jsonify({'master_private_key': private_key.decode('utf-8')}), 200


@app.route('/revoke_master_key', methods=['POST'])
def api_revoke_master_key():
    admin_id = request.json.get('admin_id')

    # Verify admin privileges
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE user_id = ?', (admin_id,))
    result = cursor.fetchone()
    if not result or not result[0]:
        conn.close()
        return jsonify({'error': 'Unauthorized. Admin privileges required.'}), 403

    revoke_master_key()
    conn.close()
    log_action(admin_id, 'revoke_master_key', 'Master private key has been revoked.')
    return jsonify({'message': 'Master private key revoked successfully.'}), 200


@app.route('/renew_master_key', methods=['POST'])
def api_renew_master_key():
    admin_id = request.json.get('admin_id')

    # Verify admin privileges
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE user_id = ?', (admin_id,))
    result = cursor.fetchone()
    if not result or not result[0]:
        conn.close()
        return jsonify({'error': 'Unauthorized. Admin privileges required.'}), 403

    generate_master_keys()
    conn.close()
    log_action(admin_id, 'renew_master_key', 'Master private key has been renewed.')
    return jsonify({'message': 'Master private key renewed successfully.'}), 200


# ----------------------------- Main Execution -----------------------------

if __name__ == '__main__':
    # Initialize database
    init_db()

    # Load or generate master keys
    load_master_keys()

    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
