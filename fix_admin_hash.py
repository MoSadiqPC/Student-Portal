# fix_admin_hash.py
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "admins.db"

def fix_admin_password():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Check if admin exists
    cur.execute("SELECT password FROM admins WHERE username = 'admin'")
    row = cur.fetchone()
    
    if row:
        current_pw = row[0]
        # If password doesn't look like a hash (simple check: length), update it
        if len(current_pw) < 50:
            print(f"Updating plain text password for 'admin'...")
            hashed_pw = generate_password_hash("admin123")
            cur.execute("UPDATE admins SET password = ? WHERE username = 'admin'", (hashed_pw,))
            conn.commit()
            print("Password updated successfully to hash.")
        else:
            print("Password already appears to be hashed.")
    else:
        print("Admin user not found.")
    
    conn.close()

if __name__ == "__main__":
    fix_admin_password()