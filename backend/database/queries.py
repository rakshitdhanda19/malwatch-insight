from database.db_connect import get_db

def get_db_connection():
    return get_db()

def get_db_connection():
    return get_db()

def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, username, email, is_admin, created_at 
            FROM users
            ORDER BY created_at DESC
        """)
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    
def log_scan(user_id, file_info, is_malicious, confidence=0.0):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO scans 
            (user_id, filename, file_path, file_size, file_type, is_malicious, confidence)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id,
            file_info['filename'],
            file_info['filepath'],
            file_info['size'],
            file_info['type'],
            is_malicious,
            confidence
        ))
        conn.commit()
        return cursor.lastrowid
    finally:
        cursor.close()
        conn.close()

def get_recent_scans(limit=10, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        query = """
            SELECT s.id, u.username, s.filename, s.file_type, 
                   s.is_malicious, s.confidence, s.created_at
            FROM scans s
            JOIN users u ON s.user_id = u.id
        """
        
        params = []
        if user_id:
            query += " WHERE s.user_id = %s"
            params.append(user_id)
        
        query += " ORDER BY s.created_at DESC LIMIT %s"
        params.append(limit)
        
        cursor.execute(query, tuple(params))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

def get_all_scans(limit=50):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT s.*, u.username 
            FROM scans s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
            LIMIT %s
        """, (limit,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()

def get_user_scans(user_id, limit=10):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM scans 
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (user_id, limit))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()    

def get_user_scan_results(user_id, limit=10):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT 
                s.filename,
                s.confidence,
                s.is_malicious,
                sr.result
            FROM scans s
            LEFT JOIN scan_results sr ON s.filename = sr.filename
            WHERE s.user_id = %s
            ORDER BY s.created_at DESC
            LIMIT %s
        """, (user_id, limit))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    