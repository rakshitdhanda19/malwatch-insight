from database.db_connect import get_db

def get_user_by_username(username):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

    
    def log_scan(user_id, file_info, is_malicious, confidence=0.0):
     conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
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
    scan_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return scan_id

    def get_recent_scans(limit=10, user_id=None):
     conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT s.id, u.username, s.filename, s.file_type, 
               s.is_malicious, s.confidence, s.created_at
        FROM scans s
        JOIN users u ON s.user_id = u.id
    """
    
    params = ()
    if user_id:
        query += " WHERE s.user_id = %s"
        params = (user_id,)
    
    query += " ORDER BY s.created_at DESC LIMIT %s"
    params += (limit,)
    
    cursor.execute(query, params)
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results