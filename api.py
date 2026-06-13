import urllib.parse
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import logging
from datetime import datetime

from db import get_db_connection, DB_PATH
from scraper import init_db, run_pipeline, create_scan_session, update_scan_session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api")

app = FastAPI(title="Threat Monitor API")

# Enable CORS for the Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all origins in local dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory state for scans
class ScanStatus(BaseModel):
    is_scanning: bool = False
    active_keyword: Optional[str] = None
    last_scan_completed: Optional[str] = None
    error: Optional[str] = None
    articles_found: int = 0
    comments_scanned: int = 0
    threats_found: int = 0
    progress_message: str = "Idle"

scan_status = ScanStatus()

class ScanRequest(BaseModel):
    keyword: str
    category: Optional[str] = "Brand Monitoring"


# Database initializer
@app.on_event("startup")
def startup():
    init_db()
    logger.info("Database initialized successfully.")

def perform_background_scan(keyword: str, scan_id: int):
    global scan_status
    conn = get_db_connection()
    try:
        logger.info(f"Starting background scan for: {keyword} (Session {scan_id})")

        # Reset counters
        scan_status.articles_found = 0
        scan_status.comments_scanned = 0
        scan_status.threats_found = 0

        # Build dynamic search URL for Google News RSS
        encoded_keyword = urllib.parse.quote(keyword)
        google_news_feed = f"https://news.google.com/rss/search?q={encoded_keyword}"

        scan_status.progress_message = f"Querying Google News RSS for '{keyword}'..."

        # Run pipeline with progress callback
        def on_progress(msg: str, articles: int = None, comments: int = None, threats: int = None):
            scan_status.progress_message = msg
            if articles is not None:
                scan_status.articles_found = articles
            if comments is not None:
                scan_status.comments_scanned = comments
            if threats is not None:
                scan_status.threats_found = threats

        stats = run_pipeline(
            conn,
            keywords=[keyword],
            feeds=[google_news_feed],
            reddit_keyword=keyword,
            progress_cb=on_progress,
            scan_id=scan_id,
        )

        update_scan_session(
            conn,
            scan_id=scan_id,
            status="completed",
            articles_found=stats.get("articles_found", 0),
            comments_scanned=stats.get("comments_scanned", 0),
            threats_high=stats.get("threats_high", 0),
            threats_medium=stats.get("threats_medium", 0),
            threats_low=stats.get("threats_low", 0),
        )

        scan_status.is_scanning = False
        scan_status.progress_message = f"Scan complete. Found {scan_status.articles_found} articles, {scan_status.threats_found} threats."
        scan_status.last_scan_completed = datetime.utcnow().isoformat()
        logger.info(f"Background scan completed for: {keyword}")
    except Exception as e:
        logger.error(f"Error during background scan: {e}")
        scan_status.is_scanning = False
        scan_status.progress_message = f"Error: {str(e)}"
        scan_status.error = str(e)
        try:
            update_scan_session(
                conn,
                scan_id=scan_id,
                status="error",
                error_message=str(e),
            )
        except Exception as db_err:
            logger.error(f"Failed to update scan session with error: {db_err}")
    finally:
        conn.close()

@app.post("/api/scan")
def trigger_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    global scan_status
    if scan_status.is_scanning:
        raise HTTPException(status_code=400, detail="A scan is already in progress.")

    if not req.keyword.strip():
        raise HTTPException(status_code=400, detail="Keyword cannot be empty.")

    # Clear seen_articles so the same keyword can be re-scanned fresh
    conn = get_db_connection()
    conn.execute("DELETE FROM seen_articles")
    conn.commit()

    # Create scan session in DB
    category = req.category or "Brand Monitoring"
    scan_id = create_scan_session(conn, req.keyword, category)
    conn.close()

    scan_status.is_scanning = True
    scan_status.active_keyword = req.keyword
    scan_status.error = None
    scan_status.progress_message = "Initializing scan..."

    # Enqueue background task
    background_tasks.add_task(perform_background_scan, req.keyword, scan_id)
    return {"message": f"Scan initiated for: {req.keyword}", "status": scan_status}

@app.get("/api/status", response_model=ScanStatus)
def get_status():
    return scan_status

@app.get("/api/results")
def get_results(severity: Optional[str] = None, search: Optional[str] = None, limit: int = 100):
    conn = get_db_connection()
    query = "SELECT * FROM flagged_comments"
    params = []
    conditions = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity.lower())

    if search:
        conditions.append("(comment_text LIKE ? OR author LIKE ?)")
        params.append(f"%{search}%")
        params.append(f"%{search}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY flagged_at DESC LIMIT ?"
    params.append(limit)

    try:
        rows = conn.execute(query, params).fetchall()
        results = [dict(row) for row in rows]
        return results
    except Exception as e:
        logger.error(f"Database query error: {e}")
        raise HTTPException(status_code=500, detail="Internal database error.")
    finally:
        conn.close()


@app.get("/api/comments")
def get_all_comments(severity: Optional[str] = None, search: Optional[str] = None, limit: int = 200):
    """Return ALL scanned comments (including safe ones) for full audit trail."""
    conn = get_db_connection()
    query = "SELECT * FROM scanned_comments"
    params = []
    conditions = []

    if severity and severity != "all":
        if severity == "safe":
            conditions.append("severity = 'none'")
        else:
            conditions.append("severity = ?")
            params.append(severity.lower())

    if search:
        conditions.append("(comment_text LIKE ? OR author LIKE ? OR article_title LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY scanned_at DESC LIMIT ?"
    params.append(limit)

    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/stats")
def get_stats():
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM flagged_comments
            GROUP BY severity
        """).fetchall()

        stats = {"high": 0, "medium": 0, "low": 0, "total": 0, "comments_scanned": 0}
        total = 0
        for row in rows:
            sev = row["severity"].lower()
            cnt = row["count"]
            if sev in stats:
                stats[sev] = cnt
            total += cnt
        stats["total"] = total

        # Total comments scanned (all)
        scanned_row = conn.execute("SELECT COUNT(*) as c FROM scanned_comments").fetchone()
        stats["comments_scanned"] = scanned_row["c"] if scanned_row else 0

        return stats
    except Exception as e:
        logger.error(f"Database query error: {e}")
        raise HTTPException(status_code=500, detail="Internal database error.")
    finally:
        conn.close()

@app.get("/api/articles")
def get_articles(limit: int = 50):
    """Return all articles that have been scanned."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT url, title, source, scraped_at FROM seen_articles ORDER BY scraped_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/scans")
def get_scan_sessions(limit: int = 50):
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Database query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/api/scans/{scan_id}")
def get_scan_session_detail(scan_id: int):
    conn = get_db_connection()
    try:
        session_row = conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (scan_id,)).fetchone()
        if not session_row:
            raise HTTPException(status_code=404, detail="Scan session not found.")
        
        # Get comments for this scan
        comment_rows = conn.execute(
            "SELECT * FROM scanned_comments WHERE scan_id = ? ORDER BY scanned_at DESC",
            (scan_id,)
        ).fetchall()
        
        # Get flagged comments for this scan
        flagged_rows = conn.execute(
            "SELECT * FROM flagged_comments WHERE scan_id = ? ORDER BY flagged_at DESC",
            (scan_id,)
        ).fetchall()
        
        return {
            "session": dict(session_row),
            "comments": [dict(row) for row in comment_rows],
            "flagged": [dict(row) for row in flagged_rows],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.delete("/api/scans/{scan_id}")
def delete_scan_session(scan_id: int):
    conn = get_db_connection()
    try:
        # Check if it exists
        session_row = conn.execute("SELECT id FROM scan_sessions WHERE id = ?", (scan_id,)).fetchone()
        if not session_row:
            raise HTTPException(status_code=404, detail="Scan session not found.")
            
        conn.execute("DELETE FROM scan_sessions WHERE id = ?", (scan_id,))
        conn.execute("DELETE FROM scanned_comments WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM flagged_comments WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return {"message": f"Scan session {scan_id} and its associated comments deleted successfully."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database delete error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.delete("/api/clear")
def clear_database():
    """Clear all flagged comments, all scanned comments, seen articles and scan sessions (fresh start)."""
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM flagged_comments")
        conn.execute("DELETE FROM scanned_comments")
        conn.execute("DELETE FROM seen_articles")
        conn.execute("DELETE FROM scan_sessions")
        conn.commit()
        return {"message": "Database cleared successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/api/sources")
def get_sources():
    """Get all unique source domains scraped, with live online/offline status."""
    import concurrent.futures
    from urllib.parse import urlparse

    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT DISTINCT source, url FROM seen_articles"
        ).fetchall()

        domain_map: dict = {}
        for row in rows:
            raw_url = row["url"] or ""
            raw_source = row["source"] or ""
            try:
                parsed = urlparse(raw_url)
                domain = parsed.netloc.replace("www.", "") if parsed.netloc else raw_source
            except Exception:
                domain = raw_source

            if domain and domain not in domain_map:
                canonical = raw_url if raw_url.startswith("http") else f"https://{domain}"
                domain_map[domain] = {
                    "domain": domain,
                    "url": canonical,
                    "status": "unknown",
                }

        domains = list(domain_map.values())

        def check_status(item: dict) -> dict:
            try:
                resp = httpx.head(item["url"], timeout=5.0, follow_redirects=True)
                item["status"] = "online" if resp.status_code < 500 else "offline"
            except Exception:
                item["status"] = "offline"
            return item

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_status, domains))

        online_count = sum(1 for r in results if r["status"] == "online")
        return {
            "sources": sorted(results, key=lambda x: x["domain"].lower()),
            "online": online_count,
            "total": len(results),
        }
    except Exception as e:
        logger.error(f"Sources query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()
