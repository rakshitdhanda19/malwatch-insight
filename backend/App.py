from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt, JWTManager, create_access_token
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
import ember
import lightgbm as lgb

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
        # Use get_jwt() to access claims
        claims = get_jwt()
        app.logger.info(f"Admin check for user: {get_jwt_identity()}, is_admin: {claims.get('is_admin')}")
        if not claims.get('is_admin'):
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper

# ML Model Initialization
try:
    # model = joblib.load(r'C:/Users/IT CITY/Downloads/malwatch-insight(1)/malwatch-insight/backend/models/malware_model.pkl')
    model = lgb.Booster(model_file="models/ember_model_2018.txt")
    print("ML model loaded successfully")
except Exception as e:
    print(f"Error loading ML model: {e}")
    model = None

def extract_features(filepath):
    """Extract features from file using ember for malware detection (2381 features)."""
    try:
        with open(filepath, 'rb') as f:
            bytez = f.read()
        # Use ember to create the feature vector (2381 features for EMBER 2018 model)
        features = ember.create_vector(bytez)
        # Ensure the features are in a format compatible with lightgbm (numpy array, 2D)
        return np.array([features])

    except Exception as e:
        print(f"Feature extraction error with ember: {e}")
        # Return a vector of zeros with the expected EMBER size if extraction fails
        return np.zeros((1, 2381)) # EMBER 2018 model expects 2381 features

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

# For verify-token endpoint
@app.route('/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        # Get user ID from token
        user_id = get_jwt_identity()
        
        # Get claims from token
        claims = get_jwt()
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, is_admin FROM users WHERE id = %s", (user_id,))
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
        # Get user ID
        user_id = get_jwt_identity()
        
        # Get claims which include is_admin status
        claims = get_jwt()
        
        # Debug logging
        app.logger.info(f"User accessing /admin/users: {user_id}, claims: {claims}")
        
        if not claims.get('is_admin'):
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
        # Get user ID
        user_id = get_jwt_identity()
        
        # Get claims which include is_admin status
        claims = get_jwt()
        
        # Debug logging
        app.logger.info(f"User accessing /admin/scans: {user_id}, claims: {claims}")
        
        if not claims.get('is_admin'):
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

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    try:
        # Get claims which include is_admin status
        claims = get_jwt()
        
        if not claims.get('is_admin'):
            return jsonify({"error": "Admin access required"}), 403
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Prevent deleting yourself
        current_user_id = get_jwt_identity()
        if int(current_user_id) == user_id:
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

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        # Debug information
        print("Upload request received")
        print(f"Files in request: {request.files}")
        print(f"Form data: {request.form}")
        
        # First check if the file exists in the requestz
        if 'file' not in request.files:
            # print("Error: No file part in the request")
            print(f"requeted test : {request.files}")
            return jsonify({"error": "No file part in the request"}), 400
        
        file = request.files['file']
        print(f"File received: {file.filename}")
        
        # Check if a file was actually selected
        if file.filename == '':
            print("Error: No file selected (empty filename)")
            return jsonify({"error": "No file selected"}), 400
        
        # Verify allowed file types
        allowed_extensions = {'exe', 'dll', 'pdf', 'docx', 'zip'}
        if '.' not in file.filename:
            print("Error: Filename has no extension")
            return jsonify({"error": "Invalid file type - no extension"}), 400
            
        extension = file.filename.rsplit('.', 1)[1].lower()
        if extension not in allowed_extensions:
            print(f"Error: Invalid file extension '{extension}'. Allowed: {allowed_extensions}")
            return jsonify({"error": f"Invalid file type. Allowed types: {', '.join(allowed_extensions)}"}), 400
        
        # Secure the filename and prepare upload
        filename = secure_filename(file.filename)
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        filepath = os.path.join(upload_folder, filename)
        print(f"Saving file to {filepath}")
        
        # Save the file temporarily
        file.save(filepath)
        
        # Get current user
        user_id = get_jwt_identity()
        print(f"User ID from token: {user_id}")
        
        # Process the file with your malware detection
        is_malicious = False  # Default value
        confidence = 0.0      # Default value
        
        # Add your actual malware detection logic here
        if model is not None:
            print("Running malware detection")
            features = extract_features(filepath)
            print(f"Shape of features before model.predict: {features.shape}")

            # Use model.predict for both prediction and confidence in binary classification
            raw_prediction = model.predict(features)[0]

            # Assuming raw_prediction is the probability for the positive class (malicious)
            confidence = float(raw_prediction) # Ensure confidence is a float
            is_malicious = bool(raw_prediction > 0.5) # Use a threshold of 0.5 for binary classification

            print(f"Malware detection results: Malicious={is_malicious}, Confidence={confidence}")
        else:
            print("Warning: ML model not loaded")
        
        # Save scan results to database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            INSERT INTO scans 
            (user_id, filename, file_path, is_malicious, confidence, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """, (user_id, filename, filepath, is_malicious, confidence))
        
        conn.commit()
        scan_id = cursor.lastrowid
        print(f"Scan saved to database with ID: {scan_id}")
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "is_malicious": is_malicious,
            "confidence": confidence,
            "filename": filename
        })
        
    except Exception as e:
        error_msg = str(e)
        print(f"ERROR in upload_file: {error_msg}")
        return jsonify({
            "error": "File processing failed",
            "details": error_msg
        }), 500
        
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

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

# Helper function for malware detection (placeholder)
def your_malware_detection_function(filepath):
    # Placeholder for your malware detection logic
    # In a real implementation, this would use the model to predict
    if model is not None:
        features = extract_features(filepath)
        prediction = model.predict(features)[0]
        return bool(prediction)
    return False

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, port=5000)