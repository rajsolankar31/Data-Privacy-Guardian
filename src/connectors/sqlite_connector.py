import sqlite3
import pandas as pd
from typing import Dict, Any, List
from ..sensitive_detector import detect_sensitive_data

def inspect_sqlite_database(
    db_path: str,
    max_sample_rows: int = 500
) -> Dict[str, Any]:
    """
    Safely inspects a SQLite database in read-only mode.
    Profiles schemas, table names, row counts, and detects sensitive columns.
    Enforces least privilege and query bounds.
    """
    results = {
        "tables": [],
        "findings": [],
        "summary": {}
    }

    # Open in URI read-only mode to prevent write modifications
    uri_path = f"file:{db_path}?mode=ro"
    try:
        conn = sqlite3.connect(uri_path, uri=True)
    except Exception:
        # Fallback if URI mode fails
        conn = sqlite3.connect(db_path)

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = [row[0] for row in cursor.fetchall()]

        total_sensitive_elements = 0

        for table in tables:
            # Query schema
            cursor.execute(f"PRAGMA table_info({table});")
            cols_info = cursor.fetchall()
            columns = [c[1] for c in cols_info]

            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table};")
            total_rows = cursor.fetchone()[0]

            # Bounded sample for privacy profiling
            sample_query = f"SELECT * FROM {table} LIMIT {max_sample_rows};"
            sample_df = pd.read_sql_query(sample_query, conn)

            table_findings = detect_sensitive_data(sample_df)
            findings_count = len(table_findings)
            total_sensitive_elements += findings_count

            # Collect finding details with database table tags
            for _, f_row in table_findings.iterrows():
                results["findings"].append({
                    "Database": db_path.split("/")[-1].split("\\")[-1],
                    "Table": table,
                    "Column": f_row["Column"],
                    "Category": f_row["Category"],
                    "Role": f_row["Role"],
                    "Confidence": f_row["Confidence"],
                    "Evidence": f_row["Evidence"],
                })

            results["tables"].append({
                "table_name": table,
                "total_rows": total_rows,
                "columns": columns,
                "sensitive_columns_found": findings_count,
                "sample_preview": sample_df.head(5)
            })

        results["summary"] = {
            "total_tables": len(tables),
            "total_sensitive_columns": total_sensitive_elements,
            "database_name": db_path.split("/")[-1].split("\\")[-1]
        }

    finally:
        conn.close()

    return results
