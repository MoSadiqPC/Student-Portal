# migrate_db.py
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "students.db")

def migrate():
    if not os.path.exists(DB_PATH):
        print("Database does not exist yet. It will be created by server.py.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    try:
        # Try to add study_type column
        cur.execute("ALTER TABLE students ADD COLUMN study_type TEXT")
        print("Added study_type column.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("Column study_type already exists.")
        else:
            print(f"Error adding study_type: {e}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()