#!/usr/bin/env python
import os
import subprocess
import time
import mysql.connector
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

print("MalWatch Insight Spam Detection Setup")
print("=====================================")

# Database configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'malwatch_db',
    'port': 3306,
    'auth_plugin': 'mysql_native_password'
}

def run_sql_script(sql_file):
    """Run SQL script using mysql command line"""
    try:
        print(f"Importing SQL schema from {sql_file}...")
        
        # For Windows
        if os.name == 'nt':
            # Try to use the mysql command in PATH
            command = [
                'mysql',
                '-h', db_config['host'],
                '-u', db_config['user'],
                f"-p{db_config['password']}",
                '-P', str(db_config['port']),
                db_config['database'],
                '<', sql_file
            ]
            cmd_str = ' '.join(command)
            process = subprocess.Popen(cmd_str, shell=True)
            process.wait()
        else:
            # For Unix systems
            command = [
                'mysql',
                '-h', db_config['host'],
                '-u', db_config['user'],
                f"-p{db_config['password']}",
                '-P', str(db_config['port']),
                db_config['database']
            ]
            with open(sql_file, 'r') as f:
                sql_content = f.read()
            
            process = subprocess.Popen(
                command, 
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate(input=sql_content.encode())
            
            if stderr:
                print(f"MySQL Error: {stderr.decode()}")
                return False
        
        return True
    except Exception as e:
        print(f"Error running SQL script: {str(e)}")
        return False

def run_python_script(script_file):
    """Run a Python script"""
    try:
        print(f"Running {script_file}...")
        
        # For both Windows and Unix
        process = subprocess.Popen(
            ['python', script_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Print output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
        
        # Get any errors
        stderr = process.stderr.read()
        if stderr:
            print(f"Error: {stderr}")
            return False
            
        return process.returncode == 0
    except Exception as e:
        print(f"Error running Python script: {str(e)}")
        return False

def setup_db_manually():
    """Import SQL manually using connector"""
    try:
        print("Attempting to import SQL schema manually...")
        conn = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password'],
            database=db_config['database'],
            port=db_config['port']
        )
        
        cursor = conn.cursor()
        
        # Read SQL file
        with open('backend/spam_schema.sql', 'r') as f:
            sql_script = f.read()
            
        # Split into individual statements
        statements = sql_script.split(';')
        
        # Execute each statement
        for statement in statements:
            if statement.strip():
                cursor.execute(statement)
                
        conn.commit()
        print("Schema imported successfully!")
        return True
    except Exception as e:
        print(f"Error setting up database manually: {str(e)}")
        return False
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def main():
    print("Step 1: Setting up database schema")
    success = run_sql_script('backend/spam_schema.sql')
    
    if not success:
        print("Trying alternative method...")
        success = setup_db_manually()
        
    if not success:
        print("Failed to set up database schema. Please import manually.")
        return
        
    print("\nStep 2: Training spam detection model")
    success = run_python_script(r'C:/Users/IT CITY/Downloads/malwatch-insight(1)/malwatch-insight/backend/train_spam_model.py')
    
    if not success:
        print("Failed to train model. Please run the training script manually.")
        return
        
    print("\nStep 3: Verifying setup")
    try:
        import joblib
        
        # Check if model files exist
        model_file = 'backend/spam_model.pkl'
        vectorizer_file = 'backend/spam_vectorizer.pkl'
        
        if os.path.exists(model_file) and os.path.exists(vectorizer_file):
            print("Model files found!")
            
            # Try to load models
            model = joblib.load(model_file)
            vectorizer = joblib.load(vectorizer_file)
            
            print("Models loaded successfully!")
            print("\nSpam detection setup complete!")
            print("You can now use the spam detection feature in MalWatch Insight.")
        else:
            print("Model files not found. Setup incomplete.")
    except Exception as e:
        print(f"Verification failed: {str(e)}")

if __name__ == "__main__":
    main() 