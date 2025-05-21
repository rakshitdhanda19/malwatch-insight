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
import pandas as pd
import hashlib
import pefile
from functools import wraps
from datetime import datetime
from flask import Flask, request, jsonify
import joblib
import numpy as np
from tensorflow.keras.models import load_model
import tensorflow as tf
from feature_extractor import extract_features
from werkzeug.utils import secure_filename






# Load models and scaler
rf_model = joblib.load('models/random_forest_model.joblib')
scaler = joblib.load('models/scaler.joblib')
lstm_model = tf.keras.models.load_model('models/lstm_model.keras')  # Optional

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
        # Get user ID and admin status from JWT
        user_id = get_jwt_identity()
        claims = get_jwt()
        
        app.logger.info(f"User accessing /admin/scans: {user_id}, claims: {claims}")
        
        if not claims.get('is_admin'):
            return jsonify({"error": "Admin access required"}), 403
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT scan_results.*, users.username 
            FROM scan_results
            JOIN users ON scan_results.user_id = users.id
            ORDER BY scan_results.created_at DESC
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


       

# @app.route('/upload', methods=['POST'])
# @jwt_required()
# def upload_file():
#     try:
#         # Debug information
#         print("Upload request received")
#         print(f"Files in request: {request.files}")
#         print(f"Form data: {request.form}")
        
#         # First check if the file exists in the requestz
#         if 'file' not in request.files:
#             # print("Error: No file part in the request")
#             print(f"requeted test : {request.files}")
#             return jsonify({"error": "No file part in the request"}), 400
        
#         file = request.files['file']
#         print(f"File received: {file.filename}")
        
#         # Check if a file was actually selected
#         if file.filename == '':
#             print("Error: No file selected (empty filename)")
#             return jsonify({"error": "No file selected"}), 400
        
#         # Verify allowed file types
#         allowed_extensions = {'exe', 'dll', 'pdf', 'docx', 'zip'}
#         if '.' not in file.filename:
#             print("Error: Filename has no extension")
#             return jsonify({"error": "Invalid file type - no extension"}), 400
            
#         extension = file.filename.rsplit('.', 1)[1].lower()
#         if extension not in allowed_extensions:
#             print(f"Error: Invalid file extension '{extension}'. Allowed: {allowed_extensions}")
#             return jsonify({"error": f"Invalid file type. Allowed types: {', '.join(allowed_extensions)}"}), 400
        
#         # Secure the filename and prepare upload
#         filename = secure_filename(file.filename)
#         upload_folder = app.config['UPLOAD_FOLDER']
#         os.makedirs(upload_folder, exist_ok=True)
#         filepath = os.path.join(upload_folder, filename)
#         print(f"Saving file to {filepath}")
        
#         # Save the file temporarily
#         file.save(filepath)
        
#         # Get current user
#         user_id = get_jwt_identity()
#         print(f"User ID from token: {user_id}")
        
#         # Process the file with your malware detection
#         is_malicious = False  # Default value
#         confidence = 0.0      # Default value
        
#         # Add your actual malware detection logic here
#         if model is not None:
#             print("Running malware detection")
#             features = extract_features(filepath)
#             print(f"Shape of features before model.predict: {features.shape}")

#             # Use model.predict for both prediction and confidence in binary classification
#             raw_prediction = model.predict(features)[0]

#             # Assuming raw_prediction is the probability for the positive class (malicious)
#             confidence = float(raw_prediction) # Ensure confidence is a float
#             is_malicious = bool(raw_prediction > 0.5) # Use a threshold of 0.5 for binary classification

#             print(f"Malware detection results: Malicious={is_malicious}, Confidence={confidence}")
#         else:
#             print("Warning: ML model not loaded")
        
#         # Save scan results to database
#         conn = get_db_connection()
#         cursor = conn.cursor(dictionary=True)
#         cursor.execute("""
#             INSERT INTO scans 
#             (user_id, filename, file_path, is_malicious, confidence, created_at)
#             VALUES (%s, %s, %s, %s, %s, NOW())
#         """, (user_id, filename, filepath, is_malicious, confidence))
        
#         conn.commit()
#         scan_id = cursor.lastrowid
#         print(f"Scan saved to database with ID: {scan_id}")
        
#         return jsonify({
#             "success": True,
#             "scan_id": scan_id,
#             "is_malicious": is_malicious,
#             "confidence": confidence,
#             "filename": filename
#         })
        
#     except Exception as e:
#         error_msg = str(e)
#         print(f"ERROR in upload_file: {error_msg}")
#         return jsonify({
#             "error": "File processing failed",
#             "details": error_msg
#         }), 500
        
#     finally:
#         if 'conn' in locals() and conn.is_connected():
#             cursor.close()
#             conn.close()
# @app.route('/upload', methods=['POST'])
# @jwt_required()
# def upload_file():
#     try:
#         if 'file' not in request.files:
#             return jsonify({"error": "No file part in request"}), 400

#         file = request.files['file']
#         if file.filename == '':
#             return jsonify({"error": "No file selected"}), 400

#         allowed_extensions = {'exe', 'dll', 'pdf', 'docx', 'zip'}
#         if '.' not in file.filename:
#             return jsonify({"error": "File has no extension"}), 400

#         ext = file.filename.rsplit('.', 1)[1].lower()
#         if ext not in allowed_extensions:
#             return jsonify({"error": f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"}), 400

#         filename = secure_filename(file.filename)
#         upload_folder = app.config['UPLOAD_FOLDER']
#         os.makedirs(upload_folder, exist_ok=True)
#         filepath = os.path.join(upload_folder, filename)
#         file.save(filepath)

#         user_id = get_jwt_identity()

#         # === Feature Extraction ===
#         try:
#             features = extract_features(filepath)  # shape: (1, N)
#             features_scaled = scaler.transform(features)  # scale for RF
#         except Exception as e:
#             return jsonify({"error": "Feature extraction failed", "details": str(e)}), 500

#         # === Prediction ===
#         try:
#             prob = rf_model.predict_proba(features_scaled)[0][1]  # Probability of malicious
#             is_malicious = prob > 0.5
#         except Exception as e:
#             return jsonify({"error": "Model prediction failed", "details": str(e)}), 500

#         # === Save to DB ===
#         try:
#             conn = get_db_connection()
#             cursor = conn.cursor(dictionary=True)
#             cursor.execute("""
#                 INSERT INTO scans 
#                 (user_id, filename, file_path, is_malicious, confidence, created_at)
#                 VALUES (%s, %s, %s, %s, %s, NOW())
#             """, (user_id, filename, filepath, is_malicious, float(prob)))
#             conn.commit()
#             scan_id = cursor.lastrowid
#         except Exception as e:
#             return jsonify({"error": "Database insert failed", "details": str(e)}), 500
#         finally:
#             if 'conn' in locals() and conn.is_connected():
#                 cursor.close()
#                 conn.close()

#         return jsonify({
#             "success": True,
#             "scan_id": scan_id,
#             "filename": filename,
#             "is_malicious": is_malicious,
#             "confidence": float(prob)
#         })

#     except Exception as e:
#         import traceback
#         return jsonify({
#             "error": "File processing failed",
#             "details": traceback.format_exc()
#         }), 500
# @app.route('/upload', methods=['POST'])
# def upload_file():
#     if 'file' not in request.files:
#         return jsonify({'error': 'No file part'}), 400

#     file = request.files['file']
#     if file.filename == '':
#         return jsonify({'error': 'No selected file'}), 400

#     if file and allowed_file(file.filename):
#         filename = secure_filename(file.filename)
#         filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#         file.save(filepath)

#         print("File saved to:", filepath)

#         try:
#             # Extract features from uploaded file
#             features = extract_features(filepath)
#             if features is None:
#                 raise ValueError("extract_features() returned None")

#             # Apply the scaler
#             features_scaled = scaler.transform(features)

#             # Predict probabilities and class
#             probs = rf_model.predict_proba(features_scaled)[0]
#             predicted_class = rf_model.predict(features_scaled)[0]
#             confidence = float(probs[1])  # Assuming class 1 = malicious

#             # Save result to database
#             conn = get_db_connection()
#             cursor = conn.cursor()
#             cursor.execute(
#     "INSERT INTO scan_results (filename, result, confidence) VALUES (%s, %s, %s)",
#     (filename, str(predicted_class), float(confidence))
# )

#             conn.commit()
#             conn.close()

#             return jsonify({
#                 'success': True,
    
#                 'filename': filename,
#                 'malicious': bool(predicted_class),
#                 'confidence': confidence,
#                 'result'     :result
               
#             })
        

#         except Exception as e:
#             print("Error during scanning:", str(e))
#             return jsonify({'error': str(e)}), 500

#     return jsonify({'error': 'Invalid file type'}), 400
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        print("File saved to:", filepath)

        try:
            # ==== Load model and scaler here ====
            from joblib import load
            model = load("models/random_forest_model.joblib")
            scaler = load("models/scaler.joblib")

            # ==== Your working extractor ====
            def extract_features(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        raw = f.read()

                    array = np.frombuffer(raw[:1024], dtype=np.uint8)
                    desired_length = 56
                    if len(array) < desired_length:
                        array = np.pad(array, (0, desired_length - len(array)))
                    else:
                        array = array[:desired_length]

                    return array.reshape(1, -1)
                except Exception as e:
                    print(f"[ERROR] Feature extraction failed: {e}")
                    raise e

            # ==== Extract features from uploaded file ====
            features = extract_features(filepath)
            scaled = scaler.transform(features)
            prediction = model.predict(scaled)[0]
            probs = model.predict_proba(scaled)[0]

# Ensure probability is properly extracted
            confidence = round(probs[prediction] * 100, 2)

            result = "Malicious" if prediction == 1 else "Benign"

# Set a malware type based on prediction or a simple mapping
            malware_type = "Trojan" if prediction == 1 else "SpyWare"

            # Get user ID from JWT
            user_id = get_jwt_identity()

            # Save result to DB
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_results (user_id, filename, result, confidence, malware_type)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (user_id, filename, result, confidence, malware_type)
            )
            conn.commit()
            conn.close()

            return jsonify({
                'success': True,
                'filename': filename,
                'malicious': result,
                'confidence': f"{confidence}%",
                'malware_type': malware_type
            })

        except Exception as e:
            print("Error during scanning:", str(e))
            return jsonify({'error': 'Scan failed: ' + str(e)}), 500

    return jsonify({'error': 'Invalid file type'}), 400
# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# def extract_features_from_binary(filepath):
#     # Dummy feature extractor for binary files - replace with real one
#     # For now we simulate 56 numerical features
#     return np.random.rand(1, 56)  # Make sure 56 matches training feature count

# def upload():
#     if 'file' not in request.files:
#         return jsonify({'error': 'No file part'}), 400

#     file = request.files['file']
#     if file.filename == '':
#         return jsonify({'error': 'No selected file'}), 400

#     if file and allowed_file(file.filename):
#         filename = secure_filename(file.filename)
#         filepath = os.path.join('uploads', filename)
#         file.save(filepath)

#         file_ext = filename.rsplit('.', 1)[1].lower()

#         try:
#             if file_ext == 'csv':
#                 try:
#                     df = pd.read_csv(filepath, encoding='utf-8')
#                 except UnicodeDecodeError:
#                     df = pd.read_csv(filepath, encoding='ISO-8859-1')

#                 numeric_features = df.select_dtypes(include=[np.number])
#                 if numeric_features.shape[1] != 56:
#                     return jsonify({'error': f'Expected 56 features, got {numeric_features.shape[1]}'}), 400
#                 features = scaler.transform(numeric_features)
#             else:
#                 features = extract_features_from_binary(filepath)
#                 features = scaler.transform(features)

#             # Predict using RF
#             rf_pred = rf_model.predict(features)[0]

#             # Predict using LSTM (requires reshaped input)
#             lstm_input = features.reshape((1, 1, features.shape[1]))
#             lstm_pred_probs = lstm_model.predict(lstm_input)
#             lstm_pred = np.argmax(lstm_pred_probs, axis=1)[0]

#             return jsonify({
#                 'RandomForestPrediction': str(rf_pred),
#                 'LSTMPrediction': str(lstm_pred),
#                 'Malicious': str(rf_pred).lower() != 'benign' or str(lstm_pred).lower() != 'benign'
#             })

#         except Exception as e:
#             return jsonify({'error': f'Scan failed: {str(e)}'}), 500
#     else:
#         return jsonify({'error': 'File type not allowed'}), 400



@app.route('/scans', methods=['GET'])
@jwt_required()
def get_user_scans():
    try:
        user_id = get_jwt_identity()
        
        if not user_id:
            return jsonify({"error": "Invalid user identity"}), 401
            
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, filename, result AS is_malicious, confidence, malware_type, created_at
            FROM scan_results 
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

# def your_malware_detection_function(filepath):
#     try:
#         features = extract_features(filepath)
#         if features is None:
#             raise ValueError("Feature extraction failed.")

#         scaled_features = scaler.transform([features])  # Assume StandardScaler used
        
#         prediction = model.predict(scaled_features)[0]
#         confidence = model.predict_proba(scaled_features)[0][prediction]
        
#         result = "Malicious" if prediction == 1 else "Benign"
        
#         # Add malware type classification logic (if malicious)
#         malware_type = "Unknown"
#         if result == "Malicious":
#             # Custom logic based on extracted features or filename (for demo)
#             if "encrypt" in filepath.lower():
#                 malware_type = "Ransomware"
#             elif "keylog" in filepath.lower() or "spy" in filepath.lower():
#                 malware_type = "Spyware"
#             else:
#                 malware_type = "trojan"
#         else:
#             malware_type = "None"
        
#         return {
#             "result": result,
#             "confidence": float(confidence),
#             "malware_type": malware_type
#         }
#     except Exception as e:
#         return {
#             "result": "Error",
#             "confidence": 0.0,
#             "malware_type": "Error",
#             "error": str(e)
#         }

# @app.route('/scan', methods=['POST'])
# def scan_file():
#     data = request.get_json()
#     filepath = data.get('filepath')

#     if not filepath or not os.path.isfile(filepath):
#         return jsonify({'error': 'Invalid or missing file path'}), 400

#     try:
#         # Expect CSV with a single row of numeric features (no label)
#         df = pd.read_csv(filepath)
#         if 'label' in df.columns:
#             df = df.drop(columns=['label'])

#         # Scale features and reshape
#         features = scaler.transform(df)
#         lstm_input = features.reshape((1, 1, features.shape[1]))

#         # Make predictions
#         rf_pred = rf_model.predict(features)[0]
#         lstm_pred = np.argmax(lstm_model.predict(lstm_input), axis=1)[0]

#         return jsonify({
#             'rf_prediction': label_map.get(rf_pred, str(rf_pred)),
#             'lstm_prediction': label_map.get(lstm_pred, str(lstm_pred))
#         })

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
# @app.route('/scan', methods=['POST'])
# def scan_file():
#     data = request.get_json()
#     filepath = data.get('filepath')

#     if not filepath or not os.path.isfile(filepath):
#         return jsonify({'error': 'Invalid or missing file path'}), 400

#     try:
#         # Expect CSV with a single row of numeric features (no label)
#         df = pd.read_csv(filepath)
#         if 'label' in df.columns:
#             df = df.drop(columns=['label'])

#         # Scale features and reshape
#         features = scaler.transform(df)
#         lstm_input = features.reshape((1, 1, features.shape[1]))

#         # Make predictions
#         rf_pred = rf_model.predict(features)[0]
#         lstm_pred = np.argmax(lstm_model.predict(lstm_input), axis=1)[0]

#         return jsonify({
#             'rf_prediction': label_map.get(rf_pred, str(rf_pred)),
#             'lstm_prediction': label_map.get(lstm_pred, str(lstm_pred))
#         })

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, port=5000)


