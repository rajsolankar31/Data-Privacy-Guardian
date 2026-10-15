import sqlite3
import os

def create_sample_sqlite_db():
    db_path = os.path.join(os.path.dirname(__file__), "..", "sample_data", "sample_hospital.db")
    db_path = os.path.abspath(db_path)
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY,
            patient_name TEXT,
            email TEXT,
            phone TEXT,
            age INTEGER,
            zip_code TEXT,
            condition TEXT,
            billing_amount REAL
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS staff (
            staff_id INTEGER PRIMARY KEY,
            doctor_name TEXT,
            department TEXT,
            work_email TEXT,
            ssn TEXT
        );
    """)
    c.execute("""
        INSERT OR IGNORE INTO patients VALUES 
        (1, 'Robert Vance', 'rvance@refrigeration.com', '555-432-1098', 55, '94016', 'Cardiac Arrest', 45000.0),
        (2, 'Phyllis Lapin', 'phyllis@dunder.com', '555-901-2345', 54, '94016', 'Rheumatism', 12000.0),
        (3, 'Michael Scott', 'michael@dunder.com', '555-111-2222', 43, '94102', 'Foot Burn', 350.0);
    """)
    c.execute("""
        INSERT OR IGNORE INTO staff VALUES 
        (101, 'Dr. Gregory House', 'Diagnostics', 'ghouse@princeton.edu', '000-11-2222'),
        (102, 'Dr. James Wilson', 'Oncology', 'jwilson@princeton.edu', '000-22-3333');
    """)
    conn.commit()
    conn.close()
    return db_path

if __name__ == "__main__":
    path = create_sample_sqlite_db()
    print("Database ready at:", path)
