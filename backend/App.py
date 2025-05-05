from flask_jwt_extended import jwt_required, get_jwt_identity, JWTManager, create_access_token
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import mysql.connector
import bcrypt
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import joblib
import numpy as np
import hashlib
import pefile
from functools import wraps
from datetime import datetime

# Load environment variables
load_dotenv()
print("Loaded JWT_SECRET from .env:", os.getenv('JWT_SECRET'))

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

# Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'exe', 'dll', 'pdf', 'docx', 'zip'}
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour expiration
jwt = JWTManager(app)

# Database configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'malwatch_db',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

# Database connection pool
db_pool = mysql.connector.pooling.MySQLConnectionPool(pool_name="mypool", pool_size=5, **db_config)

def get_db_connection():
    return db_pool.get_connection()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if not current_user.get('is_admin'):
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

# ML Model Initialization
try:
    model = joblib.load('malware_model.pkl')
    print("ML model loaded successfully")
except Exception as e:
    print(f"Error loading ML model: {e}")
    model = None

def extract_features(filepath):
    """Extract features from file for malware detection"""
    features = []
    try:
        # File size
        file_size = os.path.getsize(filepath)
        features.append(file_size)
        
        # Hash features
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
            features.append(int(hashlib.md5(file_bytes).hexdigest()[:8], 16))
            features.append(int(hashlib.sha256(file_bytes).hexdigest()[:8], 16))
        
        # PE header features (for executables)
        if filepath.endswith(('.exe', '.dll')):
            pe = pefile.PE(filepath)
            features.append(len(pe.sections))
            features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            features.append(pe.OPTIONAL_HEADER.DllCharacteristics)
        else:
            features.extend([0, 0, 0])
            
    except Exception as e:
        print(f"Feature extraction error: {e}")
        features.extend([0]*6)
        
    return np.array([features])

# Routes
@app.route('/')
def home():
    return jsonify({"status": "MalWatch Insight Backend Running!"})

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    required_fields = ['username', 'email', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if username exists
        cursor.execute("SELECT id FROM users WHERE username = %s", (data['username'],))
        if cursor.fetchone():
            return jsonify({"error": "Username already exists"}), 400
            
        hashed_pw = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, password, email, is_admin) VALUES (%s, %s, %s, %s)",
            (data['username'], hashed_pw.decode(), data['email'], False)
        )
        conn.commit()
        return jsonify({"success": True, "message": "User registered successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()  # Use get_json() instead of request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        if not bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        # Create token with additional claims
        additional_claims = {
            "is_admin": user['is_admin'],
            "username": user['username']
        }
        access_token = create_access_token(
            identity=user['id'],
            additional_claims=additional_claims
        )
        
        return jsonify({
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "is_admin": user['is_admin']
            }
        }), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        current_user = get_jwt_identity()
        
        # Verify the token structure is correct
        if not current_user or 'id' not in current_user:
            return jsonify({"error": "Invalid token structure"}), 422
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, username, is_admin 
            FROM users 
            WHERE id = %s
        """, (current_user['id'],))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({
            "user": {
                "id": user['id'],
                "username": user['username'],
                "is_admin": bool(user['is_admin'])  # Ensure boolean
            }
        }), 200
        
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        return jsonify({"error": "Token verification failed"}), 401
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400
    
    try:
        filename = secure_filename(file.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        current_user = get_jwt_identity()
        prediction = None
        confidence = None
        
        if model:
            try:
                features = extract_features(filepath)
                prediction = bool(model.predict(features)[0])
                confidence = float(model.predict_proba(features)[0][1])
            except Exception as e:
                print(f"Prediction error: {e}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO scans 
               (user_id, filename, file_path, file_size, file_type, is_malicious, confidence, created_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                current_user['id'],
                filename,
                filepath,
                os.path.getsize(filepath),
                filename.rsplit('.', 1)[1].lower(),
                prediction,
                confidence,
                datetime.now()
            )
        )
        conn.commit()
        
        return jsonify({
            "filename": filename,
            "is_malicious": prediction,
            "confidence": confidence,
            "message": "File scanned successfully"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/scans', methods=['GET'])
@jwt_required()
def get_scans():
    current_user = get_jwt_identity()
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        if current_user.get('is_admin'):
            cursor.execute(""" 
                SELECT scans.*, users.username 
                FROM scans 
                JOIN users ON scans.user_id = users.id
                ORDER BY scans.created_at DESC
            """)
        else:
            cursor.execute(""" 
                SELECT * FROM scans 
                WHERE user_id = %s 
                ORDER BY created_at DESC
            """, (current_user['id'],))
        
        scans = cursor.fetchall()
        return jsonify({"scans": scans})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/admin/users', methods=['GET'])
@admin_required
def get_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email, is_admin, created_at FROM users")
        users = cursor.fetchall()
        return jsonify({"users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, port=5000)