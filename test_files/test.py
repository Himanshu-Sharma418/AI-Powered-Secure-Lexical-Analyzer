import sqlite3
import subprocess
from pathlib import Path

# SQL section
def run_sql_queries(db_path="example.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL
        );
    """)

    # Insert data
    cursor.execute(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        ("Alice", "alice@example.com")
    )
    cursor.execute(
        "INSERT INTO users (name, email) VALUES (?, ?)",
        ("Bob", "bob@example.com")
    )

    conn.commit()

    # Query data
    cursor.execute("SELECT id, name, email FROM users;")
    rows = cursor.fetchall()

    print("SQL QUERY RESULTS:")
    for row in rows:
        print(row)

    conn.close()

# Bash section
def run_bash_commands():
    """
    Run bash commands using subprocess.
    """
    print("\nBASH COMMAND RESULTS:")

    # Example 1: List files
    result = subprocess.run(
        ["ls", "-la"],
        capture_output=True,
        text=True,
        check=False
    )
    print("ls -la output:")
    print(result.stdout)

    # Example 2: Disk usage
    result = subprocess.run(
        ["df", "-h"],
        capture_output=True,
        text=True,
        check=False
    )
    print("df -h output:")
    print(result.stdout)

    # Example 3: Using a shell pipeline
    result = subprocess.run(
        "ps aux | grep python",
        shell=True,
        capture_output=True,
        text=True
    )
    print("ps aux | grep python output:")
    print(result.stdout)

def main():
    run_sql_queries()
    run_bash_commands()


if __name__ == "__main__":
    main()
