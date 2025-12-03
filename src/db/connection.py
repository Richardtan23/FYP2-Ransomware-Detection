# src/db/connection.py
import os
from datetime import datetime
from mysql.connector import connect, Error
from dotenv import load_dotenv, find_dotenv

# Load environment variables from .env at project root
load_dotenv(find_dotenv())

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_NAME = os.getenv("DB_NAME", "ransomware_db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

def get_connection():
    """
    Create a new MySQL connection using .env values.
    """
    try:
        conn = connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME,
            port=DB_PORT,
            autocommit=True,   
        )
        return conn
    except Error as e:
        print("❌ Error while connecting to MySQL:", e)
        return None

def insert_log(filename: str, verdict: str, probability: float):
    conn = get_connection()
    if not conn:
        return

    try:
        with conn.cursor() as cur:
            # Either use Python datetime...
            cur.execute(
                """
                INSERT INTO detection_logs (filename, verdict, probability, timestamp)
                VALUES (%s, %s, %s, %s)
                """,
                (filename, verdict, float(probability), datetime.now()),
            )

    except Error as e:
        print("❌ Error inserting log:", e)
    finally:
        conn.close()

def fetch_logs(limit: int = 20):
    """
    Return the most recent 'limit' rows as a list of dicts.
    """
    conn = get_connection()
    if not conn:
        return []

    try:
        with conn.cursor(dictionary=True) as cur:
            cur.execute(
                f"""
                SELECT id, filename, verdict, probability, timestamp
                FROM detection_logs
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
            return rows
    except Error as e:
        print("❌ Error fetching logs:", e)
        return []
    finally:
        conn.close()
