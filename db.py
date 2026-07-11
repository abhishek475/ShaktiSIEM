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

def ping_db():
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return True
    except Exception:
        return False

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
                    (source,incident_type,severity,description,username,ip,command,event_time,artifact,event_action)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,(source,incident_type,severity,description,username,ip,command,time_stamp,artifact,event_action)
                    )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Incident saved: {incident_type}")
    except Exception as e:
        print(f"Error saving incident: {e}")

def fetch_user(user):
    """Login lookup. Only returns ACTIVE (not deactivated) accounts."""
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute(""" 
                    SELECT * FROM users
                    WHERE username = %s AND is_active = TRUE
                    """,(user,))
        
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        return row
    
    except Exception as e:
        print(f"Error retrieving user_details : {e}")
        return None
    
def save_login_session(user_id,ip):
    """
    Creates a new session row. Before doing so, closes any other still-active
    sessions this same user had (e.g. from closing the browser without
    logging out), so the Sessions page never shows the same user 'online'
    more than once.
    """
    try:   
        conn = get_connection()
        cursor = conn.cursor()

        # close any stale/duplicate sessions for this user first
        cursor.execute("""
                        UPDATE active_sessions
                        SET is_active = FALSE, logout_at = now()
                        WHERE user_id = %s AND is_active = TRUE
                    """,(user_id,))

        cursor.execute("""
                        INSERT INTO active_sessions
                    (user_id,ip_address)
                    VALUES(%s,%s) RETURNING id""",(user_id,ip)
                    )
        
        id_session = cursor.fetchone()[0]
        
        conn.commit()
        cursor.close()
        conn.close()
        return id_session
    except Exception as e:
        print(f"Error saving login session: {e}")
        return None

def logout_session(id_session):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        UPDATE active_sessions
                        SET is_active = FALSE,logout_at = now()
                        WHERE id = %s
                        """,(id_session,)
                    )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error changing logout status: {e}")


def fetch_user_by_id(user_id):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                        SELECT * FROM users
                        WHERE id = %s
                    """,(user_id,)
                    )
        user_details = cursor.fetchone()
        cursor.close()
        conn.close()

        return user_details
    except Exception as e:
        print(f"Error in fetching user details: {e}")
        return {}

def severity_count():
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                    SELECT
                    COUNT(*) FILTER (WHERE severity >= 70) AS critical,
                    COUNT(*) FILTER (WHERE severity >= 50 AND severity < 70) AS high,
                    COUNT(*) FILTER (WHERE severity >= 30 AND severity < 50) AS medium,
                    COUNT(*) FILTER (WHERE severity < 30) AS low
                    FROM incidents
                    """)
        counts = cursor.fetchone()
        cursor.close()
        conn.close()
        return counts
    
    except Exception as e:
        print(f"Error fetching severity count: {e}")
        return{"critical":0,"high":0,"medium":0,"low":0}
    
def get_recent_incidents(limit=5):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                    SELECT 
                       id,
                       incident_type,
                       source,
                       COALESCE(username,artifact) AS artifact_actor,
                       ip,
                       status,
                       TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI') AS created_at
                    FROM incidents
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,(limit,))
        incidents = cursor.fetchall()
        cursor.close()
        conn.close()
        return incidents
    except Exception as e:
        print(f"Error fetching recent incidents: {e}")
        return []
    
def dashboard_logins():
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                       SELECT
                        COUNT(*) AS active_logins,
                        COUNT(*) FILTER (WHERE u.role = 'analyst') AS analyst_on_shift
                        FROM active_sessions s
                        JOIN users u ON u.id = s.user_id
                        WHERE s.is_active = TRUE
                    """)
        active_user_count = cursor.fetchone()
        cursor.close()
        conn.close()
        return active_user_count
    
    except Exception as e:
        print(f"Error fetching active user data: {e}")
        return {"active_logins":0,"analyst_on_shift":0}

def fetch_incidents(status = None,source = None,severity = None):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        query = "SELECT *, TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI') AS created_at_display FROM incidents WHERE TRUE"
        params = []
        if status:
            query += " AND status = %s"
            params.append(status)
        if source:
            query += " AND source = %s"
            params.append(source)
        if severity:
            if severity == "critical":
                query += " AND severity >= 70"
            elif severity == "high":
                query += " AND severity >= 50 AND severity < 70"
            elif severity == "medium":
                query += " AND severity >= 30 AND severity < 50"
            elif severity == "low":
                query += " AND severity < 30"
            
        query += " ORDER BY created_at DESC"

        cursor.execute(query, params)
        incidents = cursor.fetchall()
        cursor.close()
        conn.close()
        return incidents
    except Exception as e:
        print(f"Error fetching incidents: {e}")
        return []
    
def fetch_incident_by_id(incident_id):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                        SELECT *,
                               TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI') AS created_at_display,
                               TO_CHAR(event_time, 'YYYY-MM-DD HH24:MI') AS event_time_display
                        FROM incidents
                        WHERE id = %s
                    """,(incident_id,)
                    )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row
    except Exception as e:
        print(f"Error fetching incidents by id: {e}")
        return {}

def fetch_notes_by_id(incident_id):
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                        SELECT n.id, n.content, TO_CHAR(n.added_at, 'YYYY-MM-DD HH24:MI') AS added_at, u.username AS added_by
                        FROM notes n
                        JOIN users u ON u.id = n.added_by
                        WHERE n.incident_id = %s
                        ORDER BY n.added_at ASC
                    """,(incident_id,))
        notes = cursor.fetchall()
        cursor.close()
        conn.close()
        return notes
    except Exception as e:
        print(f"Error fetching notes by id: {e}")
        return []
    
def add_note(incident_id,added_by,content):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        INSERT INTO notes
                       (incident_id,added_by,content)
                       VALUES(%s,%s,%s)
                    """,(incident_id,added_by,content)
                    )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error adding note: {e}")

def update_status(incident_id,status):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        UPDATE incidents
                        SET status = %s
                        WHERE id = %s
                    """,(status,incident_id)
                    )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error updating status: {e}")

def assign_incident(incident_id,assigned_to):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        UPDATE incidents
                        SET assigned_to = %s
                        WHERE id = %s
                    """,(assigned_to,incident_id))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error assigning incident: {e}")

def fetch_all_users():
    """Includes is_active so the admin page can show/hide Deactivate vs Reactivate."""
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                        SELECT id,username,role,is_active,TO_CHAR(created_at, 'YYYY-MM-DD HH24:MI') AS created_at
                        FROM users
                        ORDER BY created_at DESC
                    """)
        
        details = cursor.fetchall()
        cursor.close()
        conn.close()
        return details
    
    except Exception as e:
        print(f"Error fetching user: {e}")
        return []
    
def delete_user(user_id):
    """
    SOFT delete: deactivates the account instead of removing the row.
    Keeps notes/audit/session history intact and correctly attributed.
    A deactivated user can no longer log in (see fetch_user).
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        UPDATE users
                        SET is_active = FALSE
                        WHERE id = %s
                    """,(user_id,)
                    )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error deactivating user: {e}")

def reactivate_user(user_id):
    """Undo a soft delete — restores login access."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        UPDATE users
                        SET is_active = TRUE
                        WHERE id = %s
                    """,(user_id,)
                    )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error reactivating user: {e}")

def change_role(role,user_id):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        UPDATE users
                        SET role = %s
                        WHERE id = %s
                    """,(role,user_id)
                    )
        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Error changing role: {e}")

def fetch_active_sessions():
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                        SELECT u.username,u.role,s.ip_address,s.id,TO_CHAR(s.login_at, 'YYYY-MM-DD HH24:MI') AS login_at
                        FROM active_sessions s
                        JOIN users u ON u.id = s.user_id
                        WHERE s.is_active = TRUE
                        ORDER BY s.login_at DESC
                    """)
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        return data
    except Exception as e:
        print(f"Error fetching active sessions: {e}")
        return []
    
def is_session_active(session_id):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        SELECT is_active
                        FROM active_sessions
                        WHERE id = %s
                    """,(session_id,)
                    )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row and row[0]:
            return True
        return False
    except Exception as e:
        print(f"Error checking active sessions: {e}")
        return False

def log_action(user_id,action,target_table,target_id,details):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
                        INSERT INTO audit_log
                        (user_id,action,target_table,target_id,details)
                        VALUES (%s,%s,%s,%s,%s)
                    """,(user_id,action,target_table,target_id,details)
                    )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error logging action: {e}")

def fetch_audit_log():
    try:
        conn = get_connection()
        cursor = conn.cursor(cursor_factory = RealDictCursor)

        cursor.execute("""
                        SELECT a.id, u.username, a.action, a.target_table, a.target_id, a.details, TO_CHAR(a.created_at, 'YYYY-MM-DD HH24:MI') AS created_at
                        FROM audit_log a
                        LEFT JOIN users u ON u.id = a.user_id
                        ORDER BY a.created_at DESC
                    """)
        entries = cursor.fetchall()
        cursor.close()
        conn.close()
        return entries
    except Exception as e:
        print(f"Error fetching audit log: {e}")
        return []
