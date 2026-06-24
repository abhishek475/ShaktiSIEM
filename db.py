import psycopg2
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

load_dotenv("password.env")

DB_CONFIG = {
    "host" : os.getenv("DB_HOST"),
    "port" : os.getenv("DB_PORT"),
    "database" : os.getenv("DB_NAME"),
    "user" : os.getenv("DB_USER"),
    "password" : os.getenv("DB_PASSWORD")
}

#connection
def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def get_scanner_state(filepath):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                       SELECT last_position FROM scanner_state
                       WHERE file_path = %s
                       """,(filepath,)
                       )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        print("Scanner state retrieval successfull")
        if row:
            return row["last_position"]
         
    except Exception as e:
        print(f"Database Connection Error: {e}")

def save_scanner_state(filepath,new_position):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                       UPDATE scanner_state
                       SET last_position = %s
                       WHERE file_path = %s
                    """,(new_position,filepath)
                        )
        conn.commit()
        cursor.close()
        conn.close()
        print("Scanner state saved successfully")

    except Exception as e:
        print(f"Database connection error: {e}")

#save incidents to db
def save_incident(source,incident_type,severity,description,time_stamp,username,ip,command,artifact,event_action):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                    INSERT INTO incidents
                    (source,incident_type,severity,description,username,ip,command,timestamp,artifact,event_action)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,(source,incident_type,severity,description,username,ip,command,time_stamp,artifact,event_action)
                    )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Incident saved: {incident_type}")
    except Exception as e:
        print(f"Error saving incident: {e}")

#fetch all incidents
def fetch_all_incidents():
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                    SELECT * FROM incidents 
                    ORDER BY created_at DESC
                    """)
        incidents = cursor.fetchall()
        cursor.close()
        conn.close()
        return incidents

    except Exception as e:
        print(f"Error fetching incidents: {e}")
        return []






