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
CORS(app, resources={
    r"/*": {  # Changed from /api/* to /* to cover all routes
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True,
        "expose_headers": ["Authorization"]  # Added this for JWT
    }
})


# Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['ALLOWED_EXTENSIONS'] = {'exe', 'dll', 'pdf', 'docx', 'zip'}
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # 1 hour expiration
# Add these configurations right after app creation
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_IDENTITY_CLAIM'] = 'sub'  # Explicitly set identity claim
app.config['JWT_SUBJECT_CLAIM'] = 'sub'   # Ensure subject claim is used
app.config['JWT_ERROR_MESSAGE_KEY'] = 'error'
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
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
        user = cursor.fetchone()

        if not user or not bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        # Create token with string user ID as subject
        access_token = create_access_token(
            identity=str(user['id']),  # Simple string user ID
            additional_claims={
                'username': user['username'],
                'is_admin': bool(user['is_admin'])
            }
        )

        return jsonify({
            "access_token": access_token,
            "isAdmin": bool(user['is_admin']),
            "username": user['username']
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
# @app.route('/login', methods=['POST'])
# def login():
#     try:
#         data = request.get_json()
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
#         user = cursor.fetchone()

#         if not user or not bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
#             return jsonify({"error": "Invalid credentials"}), 401

#         # Create token with proper identity claims
#         access_token = create_access_token(
#             identity={
#                 'sub': str(user['id']),  # Ensure subject is a string
#                 'username': user['username'],
#                 'is_admin': bool(user['is_admin'])
#             },
#             additional_claims={
#                 'user_id': str(user['id']),  # String conversion
#                 'is_admin': bool(user['is_admin'])
#             }
#         )

#         return jsonify({
#             "access_token": access_token,
#             "isAdmin": bool(user['is_admin']),
#             "username": user['username']
#         })

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()         
# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
#         user = cursor.fetchone()

#         if not user or not bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
#             return jsonify({"error": "Invalid credentials"}), 401

#         # Debug output
#         print(f"User {user['username']} is_admin: {bool(user['is_admin'])}")
        
#         access_token = create_access_token(identity={
#             'id': user['id'],
#             'username': user['username'],
#             'is_admin': bool(user['is_admin'])
#         },
#          additional_claims={
#             'user_id': user['id'],  # Explicit claims
#             'is_admin': bool(user['is_admin'])
#         })
        
#         return jsonify({
#             "access_token": access_token,
#             "isAdmin": bool(user['is_admin']),  # MUST be camelCase for React
#             "username": user['username']
#         })
#     except Exception as e:
#         print(f"Login error: {str(e)}")
#         return jsonify({"error": str(e)}), 500
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()           

# @app.route('/login', methods=['POST'])
# def login():
#     data = request.get_json()  # Use get_json() instead of request.json
#     if not data or 'username' not in data or 'password' not in data:
#         return jsonify({"error": "Username and password required"}), 400

#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
#         cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
#         user = cursor.fetchone()

#         if not user:
#             return jsonify({"error": "Invalid credentials"}), 401

#         if not bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
#             return jsonify({"error": "Invalid credentials"}), 401

#         # Create token with additional claims
#         additional_claims = {
#             "is_admin": user['is_admin'],
#             "username": user['username']
#         }
#         access_token = create_access_token(
#             identity=user['id'],
#             additional_claims=additional_claims
#         )
        
#         return jsonify({
#             "access_token": access_token,
#             "token_type": "bearer",
#             "user": {
#                 "id": user['id'],
#                 "username": user['username'],
#                 "is_admin": user['is_admin']
#             }
#         }), 200

#     except Exception as e:
#         print(f"Login error: {str(e)}")
#         return jsonify({"error": "Internal server error"}), 500
#     finally:
#         if 'conn' in locals() and conn.is_connected():
#             cursor.close()
#             conn.close()

# @app.route('/verify-token', methods=['GET'])
# @jwt_required()
# def verify_token():
#     try:
#         current_user = get_jwt_identity()
        
#         # Verify the token structure is correct
#         if not current_user or 'id' not in current_user:
#             return jsonify({"error": "Invalid token structure"}), 422
            
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         cursor.execute("""
#             SELECT id, username, is_admin 
#             FROM users 
#             WHERE id = %s
#         """, (current_user['id'],))
#         user = cursor.fetchone()
        
#         if not user:
#             return jsonify({"error": "User not found"}), 404
            
#         return jsonify({
#             "user": {
#                 "id": user['id'],
#                 "username": user['username'],
#                 "is_admin": bool(user['is_admin'])  # Ensure boolean
#             }
#         }), 200
        
#     except Exception as e:
#         print(f"Token verification error: {str(e)}")
#         return jsonify({"error": "Token verification failed"}), 401
#     finally:
#         if 'conn' in locals() and conn.is_connected():
#             cursor.close()
#             conn.close()

# @app.route('/verify-token', methods=['GET'])
# @jwt_required()
# def verify_token():
#     current_user = get_jwt_identity()
    
#     # Add validation
#     if not current_user or 'id' not in current_user:
#         return jsonify({"error": "Invalid token structure"}), 422
        
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
#         cursor.execute("""
#             SELECT id, username, is_admin 
#             FROM users 
#             WHERE id = %s
#         """, (current_user['id'],))
#         user = cursor.fetchone()
        
#         if not user:
#             return jsonify({"error": "User not found"}), 404
            
#         return jsonify({
#             "user": {
#                 "id": user['id'],
#                 "username": user['username'],
#                 "is_admin": bool(user['is_admin'])
#             }
#         })
#     except Exception as e:
#         return jsonify({"error": str(e)}), 401
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()
# For verify-token endpoint
@app.route('/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        current_user = get_jwt_identity()
        if not current_user or 'id' not in current_user:
            return jsonify({"error": "Invalid token structure"}), 422
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, is_admin FROM users WHERE id = %s", (current_user['id'],))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({
            "user": {
                "id": user['id'],
                "username": user['username'],
                "is_admin": bool(user['is_admin'])
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        current_user = get_jwt_identity()
        
        # Debug logging
        app.logger.info(f"User accessing /admin/users: {current_user}")
        
        if not current_user or 'is_admin' not in current_user or not current_user['is_admin']:
            return jsonify({"error": "Admin access required"}), 403
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, username, email, is_admin, created_at 
            FROM users
            ORDER BY created_at DESC
        """)
        
        users = cursor.fetchall()
        return jsonify({"users": users})
        
    except Exception as e:
        app.logger.error(f"Error in /admin/users: {str(e)}")
        return jsonify({"error": "Database error", "details": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/admin/scans', methods=['GET'])
@jwt_required()
def get_all_scans():
    try:
        current_user = get_jwt_identity()
        
        # Debug logging
        app.logger.info(f"User accessing /admin/scans: {current_user}")
        
        if not current_user or 'is_admin' not in current_user or not current_user['is_admin']:
            return jsonify({"error": "Admin access required"}), 403
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT scans.*, users.username 
            FROM scans
            JOIN users ON scans.user_id = users.id
            ORDER BY scans.created_at DESC
        """)
        
        scans = cursor.fetchall()
        return jsonify({"scans": scans})
        
    except Exception as e:
        app.logger.error(f"Error in /admin/scans: {str(e)}")
        return jsonify({"error": "Database error", "details": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

# For admin endpoints
# @app.route('/admin/users', methods=['GET'])
# @admin_required
# def get_all_users():
#     try:
#         current_user = get_jwt_identity()
#         if not current_user or 'id' not in current_user:
#             return jsonify({"error": "Invalid user identity in token"}), 422
            
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         cursor.execute("""
#             SELECT id, username, email, is_admin, created_at 
#             FROM users
#             WHERE id != %s
#             ORDER BY created_at DESC
#         """, (current_user['id'],))
        
#         users = cursor.fetchall()
#         return jsonify({
#             "users": users,
#             "message": "Users retrieved successfully"
#         })
#     except Exception as e:
#         return jsonify({
#             "error": "Database error",
#             "details": str(e)
#         }), 500
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()

# @app.route('/admin/scans', methods=['GET'])
# @admin_required
# def get_all_scans():
#     try:
#         current_user = get_jwt_identity()
#         if not current_user or 'id' not in current_user:
#             return jsonify({"error": "Invalid user identity in token"}), 422
            
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         cursor.execute("""
#             SELECT scans.*, users.username 
#             FROM scans
#             JOIN users ON scans.user_id = users.id
#             ORDER BY scans.created_at DESC
#         """)
        
#         scans = cursor.fetchall()
#         return jsonify({
#             "scans": scans,
#             "message": "Scans retrieved successfully"
#         })
#     except Exception as e:
#         return jsonify({
#             "error": "Database error",
#             "details": str(e)
#         }), 500
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Prevent deleting yourself
        current_user = get_jwt_identity()
        if current_user['id'] == user_id:
            return jsonify({"error": "Cannot delete yourself"}), 400
            
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close() 
            
# @app.route('/admin/scans', methods=['GET'])
# @admin_required
# def get_all_scans():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         cursor.execute("""
#             SELECT scans.*, users.username 
#             FROM scans
#             JOIN users ON scans.user_id = users.id
#             ORDER BY scans.created_at DESC
#         """)
#         scans = cursor.fetchall()
        
#         return jsonify({"scans": scans})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()                     
# @app.route('/upload', methods=['POST'])
# @jwt_required()
# def upload_file():
#     if 'file' not in request.files:
#         return jsonify({"error": "No file part"}), 400
    
#     file = request.files['file']
#     if file.filename == '':
#         return jsonify({"error": "No selected file"}), 400
    
#     try:
#         # Save file and process scan
#         filename = secure_filename(file.filename)
#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         file.save(filepath)
        
#         # Get current user
#         user_id = get_jwt_identity()
        
#         # Process scan (your malware detection logic)
#         is_malicious, confidence = process_file(filepath)  # Implement this
        
#         # Save to database
#         cursor = conn.cursor()
#         cursor.execute("""
#             INSERT INTO scans 
#             (user_id, filename, file_path, is_malicious, confidence)
#             VALUES (%s, %s, %s, %s, %s)
#             RETURNING id
#         """, (user_id, filename, filepath, is_malicious, confidence))
#         scan_id = cursor.fetchone()['id']
#         conn.commit()
        
#         return jsonify({
#             "message": "File scanned successfully",
#             "scan_id": scan_id,
#             "is_malicious": is_malicious,
#             "confidence": confidence
#         })
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    # First check if the file exists in the request
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    
    file = request.files['file']
    
    # Check if a file was actually selected
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Verify allowed file types
    allowed_extensions = {'exe', 'dll', 'pdf', 'docx', 'zip'}
    if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        return jsonify({"error": "Invalid file type"}), 400
    
    try:
        # Secure the filename and prepare upload
        filename = secure_filename(file.filename)
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        
        # Save the file temporarily
        file.save(filepath)
        
        # Get current user
        user_id = get_jwt_identity()
        
        # Process the file with your malware detection
        is_malicious = False  # Default value
        confidence = 0.0      # Default value
        
        # Add your actual malware detection logic here
        if your_malware_detection_function(filepath):
            is_malicious = True
            confidence = 0.95  # Example value
        
        # Save scan results to database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            INSERT INTO scans 
            (user_id, filename, file_path, is_malicious, confidence, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            RETURNING id
        """, (user_id, filename, filepath, is_malicious, confidence))
        
        scan_id = cursor.fetchone()['id']
        conn.commit()
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "filename": filename
        })
        
    except Exception as e:
        return jsonify({
            "error": "File processing failed",
            "details": str(e)
        }), 500
        
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
# @app.route('/scans', methods=['GET'])
# @jwt_required()
# def get_scans():
#     current_user = get_jwt_identity()
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         if current_user.get('is_admin'):
#             cursor.execute(""" 
#                 SELECT scans.*, users.username 
#                 FROM scans 
#                 JOIN users ON scans.user_id = users.id
#                 ORDER BY scans.created_at DESC
#             """)
#         else:
#             cursor.execute(""" 
#                 SELECT * FROM scans 
#                 WHERE user_id = %s 
#                 ORDER BY created_at DESC
#             """, (current_user['id'],))
        
#         scans = cursor.fetchall()
#         return jsonify({"scans": scans})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#     finally:
#         if 'conn' in locals() and conn.is_connected():
#             cursor.close()
#             conn.close()
@app.route('/scans', methods=['GET'])
@jwt_required()
def get_user_scans():
    try:
        # get_jwt_identity() now returns just the user ID string
        user_id = get_jwt_identity()
        
        if not user_id:
            return jsonify({"error": "Invalid user identity"}), 401
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, filename, is_malicious, confidence, created_at
            FROM scans 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, (user_id,))
        scans = cursor.fetchall()
        return jsonify({"scans": scans})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def validate_admin_request(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # Check for required headers
        if not request.headers.get('Authorization'):
            return jsonify({"error": "Missing Authorization header"}), 422
        
        # Extract token
        auth_header = request.headers['Authorization']
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Invalid token format"}), 422
        
        return f(*args, **kwargs)
    return wrapper

# @app.route('/admin/users', methods=['GET'])
# @jwt_required()  # Ensures valid JWT is present
# @admin_required  # Your custom admin check decorator
# def get_all_users():
#     conn = None
#     cursor = None
#     try:
#         # Get and verify current user
#         current_user = get_jwt_identity()
#         if not current_user:
#             return jsonify({"error": "Invalid user identity"}), 401

#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         # Improved query with parameterized inputs
#         query = """
#             SELECT 
#                 id, 
#                 username, 
#                 email, 
#                 is_admin, 
#                 created_at,
#                 last_login  # Added example additional field
#             FROM users
#             WHERE id != %s
#             ORDER BY created_at DESC
#             LIMIT 100  # Added safety limit
#         """
#         cursor.execute(query, (current_user['id'],))
        
#         users = cursor.fetchall()
        
#         # Sanitize sensitive data before returning
#         for user in users:
#             user.pop('password_hash', None)  # If accidentally selected
#             user['created_at'] = str(user['created_at'])  # Convert datetime
            
#         return jsonify({
#             "success": True,
#             "users": users,
#             "count": len(users)
#         })
        
#     except jwt.ExpiredSignatureError:
#         return jsonify({"error": "Token has expired"}), 401
#     except jwt.InvalidTokenError:
#         return jsonify({"error": "Invalid token"}), 401
#     except Exception as e:
#         app.logger.error(f"Error fetching users: {str(e)}")
#         return jsonify({
#             "error": "Failed to fetch users",
#             "details": str(e)
#         }), 500
#     finally:
#         if cursor:
#             cursor.close()
#         if conn and conn.is_connected():
#             conn.close()

# @app.route('/admin/scans', methods=['GET'])
# @admin_required
# def get_all_scans():
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
        
#         cursor.execute("""
#             SELECT scans.*, users.username 
#             FROM scans
#             JOIN users ON scans.user_id = users.id
#             ORDER BY scans.created_at DESC
#         """)
        
#         scans = cursor.fetchall()
#         return jsonify({"scans": scans})
        
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()

# @app.route('/scans', methods=['GET'])
# @jwt_required()
# def get_user_scans():
#     try:
#         user_id = get_jwt_identity()
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
#         cursor.execute("""
#             SELECT * FROM scans 
#             WHERE user_id = %s 
#             ORDER BY created_at DESC
#         """, (user_id,))
#         scans = cursor.fetchall()
#         return jsonify({"scans": scans})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#     finally:
#         if conn.is_connected():
#             cursor.close()
#             conn.close()



            


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, port=5000)