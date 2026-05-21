import os
import re
import sqlite3
from typing import Optional

DB_PATH = "threat_monitor.db"

class AegisRow:
    def __init__(self, colnames, values):
        self._colnames = colnames
        self._values = values
        self._dict = dict(zip(colnames, values))

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._dict[key]

    def keys(self):
        return self._colnames

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __repr__(self):
        return f"AegisRow({self._dict})"


class AegisCursor:
    def __init__(self, cursor, is_postgres=False):
        self.cursor = cursor
        self.is_postgres = is_postgres
        self._lastrowid = None

    @property
    def lastrowid(self):
        if self.is_postgres:
            return self._lastrowid
        else:
            return self.cursor.lastrowid

    def execute(self, sql, params=None):
        if params is None:
            params = ()
        
        # Translate query if Postgres
        if self.is_postgres:
            # 1. PRAGMA table_info translation
            pragma_match = re.match(r'PRAGMA\s+table_info\((\w+)\)', sql, re.IGNORECASE)
            if pragma_match:
                table_name = pragma_match.group(1)
                sql = """
                    SELECT 0 as cid, column_name as name, data_type as type, 
                           0 as notnull, NULL as dflt_value, 0 as pk 
                    FROM information_schema.columns 
                    WHERE table_name = %s
                """
                params = (table_name,)
            else:
                # 2. Convert placeholders from ? to %s
                sql = sql.replace('?', '%s')
                
                # 3. Replace AUTOINCREMENT with serial/identity
                sql = re.sub(r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', 'SERIAL PRIMARY KEY', sql, flags=re.IGNORECASE)
                
                # 4. Replace INSERT OR IGNORE with ON CONFLICT DO NOTHING
                if "INSERT OR IGNORE" in sql.upper():
                    sql = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO\s+(\w+)', r'INSERT INTO \1', sql, flags=re.IGNORECASE)
                    if "seen_articles" in sql:
                        sql += " ON CONFLICT (url_hash) DO NOTHING"
                
                # 5. RETURNING id for last insert id retrieval
                is_insert_with_id = sql.strip().upper().startswith("INSERT INTO") and any(t in sql for t in ["scan_sessions", "flagged_comments", "scanned_comments"])
                if is_insert_with_id and "RETURNING" not in sql.upper():
                    sql += " RETURNING id"
        else:
            # SQLite doesn't need rewrite, but let's make sure it's execute-ready
            pass
            
        # Execute query
        self.cursor.execute(sql, params)
        
        # For Postgres INSERT, fetch returning ID to set _lastrowid
        if self.is_postgres and sql.strip().upper().startswith("INSERT INTO") and any(t in sql for t in ["scan_sessions", "flagged_comments", "scanned_comments"]):
            try:
                # We need to fetch the row to get the returned ID
                row = self.cursor.fetchone()
                if row:
                    self._lastrowid = row[0]
            except Exception:
                pass
                
        return self

    def fetchone(self):
        row = self.cursor.fetchone()
        if not row:
            return None
        colnames = [desc[0] for desc in self.cursor.description]
        return AegisRow(colnames, row)

    def fetchall(self):
        rows = self.cursor.fetchall()
        if not rows:
            return []
        colnames = [desc[0] for desc in self.cursor.description]
        return [AegisRow(colnames, r) for r in rows]

    def close(self):
        self.cursor.close()

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class AegisConnection:
    def __init__(self, conn, is_postgres=False):
        self.conn = conn
        self.is_postgres = is_postgres

    def cursor(self):
        return AegisCursor(self.conn.cursor(), is_postgres=self.is_postgres)

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


def get_db_connection(path: str = DB_PATH) -> AegisConnection:
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        import psycopg2
        # Standardize postgres:// to postgresql://
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        conn = psycopg2.connect(db_url)
        return AegisConnection(conn, is_postgres=True)
    else:
        conn = sqlite3.connect(path)
        return AegisConnection(conn, is_postgres=False)
