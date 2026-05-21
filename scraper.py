"""
scraper.py — Phase 1 prototype
RSS feed poller + website comment scraper + keyword threat matcher

Dependencies:
    pip install feedparser playwright beautifulsoup4 httpx
    playwright install chromium
"""

import re
import hashlib
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import os
import feedparser
import httpx
import praw
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright

from db import get_db_connection, AegisConnection, DB_PATH


# Load optional environment variables from .env
load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration — edit this section to customise your targets
# ---------------------------------------------------------------------------

# Keywords to search for in article titles / bodies (triggers scraping)
TARGET_KEYWORDS = [
    "Elon Musk",
    "Tim Cook",
]

# Threat patterns to detect in comments (Boolean OR across all patterns)
THREAT_PATTERNS = [
    r"\bkill\b",
    r"\bmurder\b",
    r"\battack\b",
    r"\bshoot\b",
    r"\bbomb\b",
    r"\bstalk\b",
    r"\bharass\b",
    r"\bthreaten\b",
    r"\bdead\b.{0,20}\b(you|him|her|them)\b",
    r"\b(you|he|she|they).{0,20}\b(will|gonna|going to)\b.{0,20}\b(die|suffer|pay)\b",
]

# RSS feeds to monitor
RSS_FEEDS = [
    "https://feeds.bbci.co.uk/news/rss.xml",
    "https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml",
    "https://www.theguardian.com/world/rss",
]

# Poll interval in seconds (300 = every 5 minutes)
POLL_INTERVAL_SECONDS = 300

# Database file
DB_PATH = "threat_monitor.db"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Article:
    url: str
    title: str
    source: str
    published: Optional[str] = None
    url_hash: str = field(init=False)

    def __post_init__(self):
        self.url_hash = hashlib.md5(self.url.encode()).hexdigest()


@dataclass
class Comment:
    article_url: str
    author: str
    text: str
    timestamp: Optional[str]
    severity: str = "none"  # none | low | medium | high


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(conn=None):
    if conn is None:
        conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS seen_articles (
            url_hash VARCHAR(255) PRIMARY KEY,
            url TEXT,
            title TEXT,
            source TEXT,
            scraped_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS flagged_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_url TEXT,
            author TEXT,
            comment_text TEXT,
            timestamp TEXT,
            severity TEXT,
            matched_patterns TEXT,
            flagged_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scanned_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_url TEXT,
            article_title TEXT,
            author TEXT,
            comment_text TEXT,
            timestamp TEXT,
            severity TEXT,
            matched_patterns TEXT,
            scanned_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT,
            category TEXT,
            status TEXT,
            started_at TEXT,
            completed_at TEXT,
            articles_found INTEGER DEFAULT 0,
            comments_scanned INTEGER DEFAULT 0,
            threats_high INTEGER DEFAULT 0,
            threats_medium INTEGER DEFAULT 0,
            threats_low INTEGER DEFAULT 0,
            error_message TEXT
        )
    """)

    # Migrations for scan_id column
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(flagged_comments)")
    flagged_cols = [row[1] for row in cursor.fetchall()]
    if "scan_id" not in flagged_cols:
        conn.execute("ALTER TABLE flagged_comments ADD COLUMN scan_id INTEGER")

    cursor.execute("PRAGMA table_info(scanned_comments)")
    scanned_cols = [row[1] for row in cursor.fetchall()]
    if "scan_id" not in scanned_cols:
        conn.execute("ALTER TABLE scanned_comments ADD COLUMN scan_id INTEGER")

    conn.commit()
    return conn


def is_seen(conn: AegisConnection, url_hash: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM seen_articles WHERE url_hash = ?", (url_hash,)
    ).fetchone()
    return row is not None


def mark_seen(conn: AegisConnection, article: Article):
    conn.execute(
        "INSERT OR IGNORE INTO seen_articles VALUES (?, ?, ?, ?, ?)",
        (article.url_hash, article.url, article.title,
         article.source, datetime.utcnow().isoformat()),
    )
    conn.commit()


def save_flagged(conn: AegisConnection, comment: Comment, matched: list[str], scan_id: Optional[int] = None):
    conn.execute(
        """INSERT INTO flagged_comments
           (article_url, author, comment_text, timestamp, severity, matched_patterns, flagged_at, scan_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            comment.article_url,
            comment.author,
            comment.text,
            comment.timestamp,
            comment.severity,
            ", ".join(matched),
            datetime.utcnow().isoformat(),
            scan_id,
        ),
    )
    conn.commit()


def save_scanned(conn: AegisConnection, comment: Comment, article_title: str, severity: str, matched: list[str], scan_id: Optional[int] = None):
    """Persist every comment regardless of threat level for full audit trail."""
    conn.execute(
        """INSERT INTO scanned_comments
           (article_url, article_title, author, comment_text, timestamp, severity, matched_patterns, scanned_at, scan_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            comment.article_url,
            article_title,
            comment.author,
            comment.text,
            comment.timestamp,
            severity,
            ", ".join(matched),
            datetime.utcnow().isoformat(),
            scan_id,
        ),
    )
    conn.commit()


def create_scan_session(conn: AegisConnection, keyword: str, category: str) -> int:
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO scan_sessions
           (keyword, category, status, started_at)
           VALUES (?, ?, ?, ?)""",
        (keyword, category, "running", datetime.utcnow().isoformat())
    )
    conn.commit()
    return cursor.lastrowid


def update_scan_session(
    conn: AegisConnection,
    scan_id: int,
    status: str,
    completed_at: str = None,
    articles_found: int = 0,
    comments_scanned: int = 0,
    threats_high: int = 0,
    threats_medium: int = 0,
    threats_low: int = 0,
    error_message: str = None
):
    conn.execute(
        """UPDATE scan_sessions
           SET status = ?, completed_at = ?, articles_found = ?, comments_scanned = ?,
               threats_high = ?, threats_medium = ?, threats_low = ?, error_message = ?
           WHERE id = ?""",
        (status, completed_at or datetime.utcnow().isoformat(), articles_found, comments_scanned,
         threats_high, threats_medium, threats_low, error_message, scan_id)
    )
    conn.commit()



# ---------------------------------------------------------------------------
# RSS polling
# ---------------------------------------------------------------------------

def poll_rss(feed_url: str, keywords: list[str]) -> list[Article]:
    """
    Parse an RSS feed and return articles whose titles or summaries
    contain at least one of the target keywords.
    """
    log.info(f"Polling RSS: {feed_url}")
    try:
        feed = feedparser.parse(feed_url)
    except Exception as e:
        log.error(f"Failed to parse feed {feed_url}: {e}")
        return []

    articles = []
    for entry in feed.entries:
        title = entry.get("title", "")
        summary = entry.get("summary", "")
        text = f"{title} {summary}".lower()

        if any(kw.lower() in text for kw in keywords):
            url = entry.get("link", "")
            if url:
                articles.append(Article(
                    url=url,
                    title=title,
                    source=feed_url,
                    published=entry.get("published", None),
                ))

    log.info(f"  Found {len(articles)} relevant article(s)")
    return articles


# ---------------------------------------------------------------------------
# Reddit search + comment fetching
# ---------------------------------------------------------------------------

# Reddit blocks simple bot User-Agents on .json endpoints.
# RSS search is always open. Comment JSON uses old.reddit.com + browser headers.
REDDIT_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.reddit.com/",
}


def poll_reddit_search(keyword: str, limit: int = 15) -> list[Article]:
    """
    Search Reddit via its RSS search feed (never rate-limited / blocked).
    Searches both global Reddit and key high-traffic subreddits, filters to
    actual comment threads only (URLs containing /comments/).
    """
    import urllib.parse as _urlparse
    encoded = _urlparse.quote(keyword)

    # Sources: global search + active discussion subreddits
    rss_sources = [
        f"https://www.reddit.com/search.rss?q={encoded}&sort=new&limit={limit}",
        f"https://www.reddit.com/search.rss?q={encoded}&sort=top&t=week&limit={limit}",
        f"https://www.reddit.com/r/news/search.rss?q={encoded}&sort=top&t=week&restrict_sr=1&limit=10",
        f"https://www.reddit.com/r/worldnews/search.rss?q={encoded}&sort=top&t=week&restrict_sr=1&limit=10",
        f"https://www.reddit.com/r/politics/search.rss?q={encoded}&sort=top&t=week&restrict_sr=1&limit=10",
        f"https://www.reddit.com/r/technology/search.rss?q={encoded}&sort=top&t=week&restrict_sr=1&limit=10",
    ]

    seen_urls: set[str] = set()
    articles: list[Article] = []

    for rss_url in rss_sources:
        log.info(f"Searching Reddit RSS: {rss_url[:80]}")
        try:
            feed = feedparser.parse(rss_url)
            for entry in feed.entries:
                link = entry.get("link", "").rstrip("/")
                title = entry.get("title", "")
                published = entry.get("published", "")
                # Only keep actual comment threads, not subreddit/user pages
                if link and "reddit.com" in link and "/comments/" in link and link not in seen_urls:
                    seen_urls.add(link)
                    articles.append(Article(
                        url=link,
                        title=f"[Reddit] {title}",
                        source="reddit.com",
                        published=published,
                    ))
        except Exception as e:
            log.warning(f"Reddit RSS source failed ({rss_url[:60]}): {e}")

    log.info(f"  Reddit RSS total unique threads: {len(articles)}")
    return articles[:limit * 2]  # cap to avoid too many requests


_reddit_client = None

def get_reddit_client():
    global _reddit_client
    if _reddit_client is not None:
        return _reddit_client
    
    client_id = os.getenv("REDDIT_CLIENT_ID")
    client_secret = os.getenv("REDDIT_CLIENT_SECRET")
    user_agent = os.getenv("REDDIT_USER_AGENT", "AegisThreatMonitor/1.0")
    
    if client_id and client_secret:
        try:
            log.info("Initializing PRAW Reddit client...")
            _reddit_client = praw.Reddit(
                client_id=client_id,
                client_secret=client_secret,
                user_agent=user_agent
            )
            # Test connection / read-only state
            _reddit_client.read_only = True
            return _reddit_client
        except Exception as e:
            log.error(f"Failed to initialize PRAW Reddit client: {e}")
            return None
    return None


def fetch_reddit_comments(thread_url: str, article_url: str, max_comments: int = 100) -> list[Comment]:
    """
    Fetch comments from a Reddit thread.
    Uses PRAW if API credentials are configured, else falls back to old.reddit.com JSON.
    """
    reddit_client = get_reddit_client()
    if reddit_client:
        log.info(f"  Fetching Reddit comments via PRAW: {thread_url}")
        try:
            submission = reddit_client.submission(url=thread_url)
            submission.comments.replace_more(limit=0)  # flatten comments
            comments = []
            for c in submission.comments.list():
                if len(comments) >= max_comments:
                    break
                body = c.body
                author = f"u/{c.author.name}" if c.author else "unknown"
                created = str(c.created_utc) if c.created_utc else ""
                if body and body not in ("[deleted]", "[removed]") and len(body) >= 5:
                    comments.append(Comment(
                        article_url=article_url,
                        author=author,
                        text=body,
                        timestamp=created,
                    ))
            log.info(f"  PRAW Reddit comments extracted: {len(comments)}")
            return comments
        except Exception as e:
            log.warning(f"PRAW fetch failed for {thread_url}, falling back to JSON scraper: {e}")
            # fall through to JSON scraper

    # Convert to old.reddit.com for more permissive access
    clean_url = thread_url.rstrip("/")
    old_url = clean_url.replace("www.reddit.com", "old.reddit.com")
    json_url = old_url + ".json?limit=100&depth=3"
    log.info(f"  Fetching Reddit comments via fallback JSON scraper: {clean_url}")
    try:
        resp = httpx.get(
            json_url,
            timeout=20,
            headers=REDDIT_BROWSER_HEADERS,
            follow_redirects=True,
        )
        resp.raise_for_status()
        data = resp.json()

        comments: list[Comment] = []

        def parse_node(node):
            if len(comments) >= max_comments:
                return
            kind = node.get("kind")
            d = node.get("data", {})
            if kind == "t1":  # comment node
                body = d.get("body", "")
                author = d.get("author", "unknown")
                created = str(d.get("created_utc", ""))
                if body and body not in ("[deleted]", "[removed]") and len(body) >= 5:
                    comments.append(Comment(
                        article_url=article_url,
                        author=f"u/{author}",
                        text=body,
                        timestamp=created,
                    ))
                replies = d.get("replies", "")
                if isinstance(replies, dict):
                    for child in replies.get("data", {}).get("children", []):
                        parse_node(child)
            elif kind == "Listing":
                for child in d.get("children", []):
                    parse_node(child)

        # Reddit JSON: [post_listing, comment_listing]
        if isinstance(data, list) and len(data) >= 2:
            for child in data[1].get("data", {}).get("children", []):
                parse_node(child)

        log.info(f"  Reddit comments extracted: {len(comments)}")
        return comments
    except Exception as e:
        log.warning(f"Reddit comment fetch failed for {thread_url}: {e}")
        return []

# ---------------------------------------------------------------------------
# DuckDuckGo search
# ---------------------------------------------------------------------------

def poll_duckduckgo_search(keyword: str, limit: int = 10) -> list[Article]:
    """
    Search DuckDuckGo via its HTML-only interface to find discussions,
    blogs, and pages relevant to the keyword.
    """
    import urllib.parse
    log.info(f"Searching DuckDuckGo HTML for '{keyword}'")
    encoded = urllib.parse.quote(keyword)
    url = f"https://html.duckduckgo.com/html/?q={encoded}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    articles = []
    try:
        resp = httpx.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        
        soup = BeautifulSoup(resp.text, "html.parser")
        
        for a in soup.find_all("a", class_="result__snippet"):
            parent = a.parent
            title_el = parent.find("a", class_="result__url")
            if title_el:
                title = title_el.get_text(strip=True)
                link = title_el.get("href", "")
                
                # DuckDuckGo redirect URLs look like: /l/?kh=-1&uddg=https%3A%2F%2Fwww.apple.com%2F
                if "/l/?uddg=" in link:
                    parsed = urllib.parse.urlparse(link)
                    query_params = urllib.parse.parse_qs(parsed.query)
                    link = query_params.get("uddg", [link])[0]
                    
                articles.append(Article(
                    url=link,
                    title=f"[Web] {title}",
                    source="duckduckgo.com",
                ))
                if len(articles) >= limit:
                    break
    except Exception as e:
        log.warning(f"DuckDuckGo search scraper failed: {e}")
        
    log.info(f"  DuckDuckGo search total unique pages: {len(articles)}")
    return articles


# ---------------------------------------------------------------------------
# Bluesky search
# ---------------------------------------------------------------------------

def poll_bluesky_search(keyword: str, limit: int = 15) -> list[Comment]:
    """
    Search Bluesky using the public unauthenticated AppView API.
    Maps posts to Comment objects.
    """
    log.info(f"Searching Bluesky AppView API for '{keyword}'")
    url = "https://api.bsky.app/xrpc/app.bsky.feed.searchPosts"
    params = {"q": keyword, "limit": limit}
    comments = []
    try:
        resp = httpx.get(url, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        
        posts = data.get("posts", [])
        for post in posts:
            author_data = post.get("author", {})
            handle = author_data.get("handle", "unknown")
            record = post.get("record", {})
            text = record.get("text", "")
            created_at = record.get("createdAt")
            uri = post.get("uri", "")
            
            # Construct post web link
            post_id = uri.split("/")[-1] if uri else ""
            post_url = f"https://bsky.app/profile/{handle}/post/{post_id}" if post_id else uri
            
            if text and len(text) >= 5:
                comments.append(Comment(
                    article_url=post_url,
                    author=f"@{handle}",
                    text=text,
                    timestamp=created_at,
                ))
    except Exception as e:
        log.warning(f"Bluesky AppView API search failed: {e}")
        
    log.info(f"  Bluesky search total posts: {len(comments)}")
    return comments


# ---------------------------------------------------------------------------
# Comment extraction
# ---------------------------------------------------------------------------

def fetch_html_static(url: str) -> Optional[str]:
    """Fetch a page using a plain HTTP request (fast, no JS)."""
    try:
        resp = httpx.get(url, timeout=15, follow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; ThreatMonitor/1.0)"})
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        log.warning(f"Static fetch failed for {url}: {e}")
        return None


def fetch_html_dynamic(url: str) -> Optional[str]:
    """
    Fetch a page using a headless Chromium browser.
    Use this when comments load via JavaScript.
    """
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=20000)
            # Wait for comment section to appear — adjust selector as needed
            page.wait_for_timeout(3000)
            html = page.content()
            browser.close()
            return html
    except Exception as e:
        log.warning(f"Dynamic fetch failed for {url}: {e}")
        return None


def extract_comments_generic(html: str, article_url: str) -> list[Comment]:
    """
    Generic comment extractor. Tries common CSS patterns used by
    news sites and blog platforms.

    Returns a list of Comment objects. Extend this with site-specific
    extractors when you need higher accuracy.
    """
    soup = BeautifulSoup(html, "html.parser")
    comments = []

    # --- Strategy 1: elements with class names containing "comment" ---
    comment_blocks = soup.find_all(
        class_=re.compile(r"comment", re.IGNORECASE)
    )

    for block in comment_blocks:
        # Skip nav/header elements that happen to contain "comment"
        if block.name in ("nav", "header", "footer", "script", "style"):
            continue

        text = block.get_text(separator=" ", strip=True)

        # Skip very short or very long blocks (noise)
        if len(text) < 10 or len(text) > 5000:
            continue

        # Try to find author within the block
        author_el = block.find(class_=re.compile(r"author|name|user", re.IGNORECASE))
        author = author_el.get_text(strip=True) if author_el else "unknown"

        # Try to find timestamp
        time_el = block.find(["time", "abbr"])
        timestamp = time_el.get("datetime") or time_el.get_text(strip=True) if time_el else None

        comments.append(Comment(
            article_url=article_url,
            author=author,
            text=text,
            timestamp=timestamp,
        ))

    # --- Strategy 2: Disqus embed fallback ---
    # Disqus loads in an iframe; if detected, log a warning.
    if soup.find(id=re.compile(r"disqus", re.IGNORECASE)):
        log.info(f"  Disqus embed detected at {article_url} — dynamic fetch may be needed")

    log.info(f"  Extracted {len(comments)} comment(s) from {article_url}")
    return comments


# ---------------------------------------------------------------------------
# Threat detection
# ---------------------------------------------------------------------------

def score_comment(comment: Comment) -> tuple[str, list[str]]:
    """
    Run threat patterns against a comment.
    Returns (severity, matched_pattern_list).
    severity: 'none' | 'low' | 'medium' | 'high'
    """
    text = comment.text.lower()
    matched = []

    for pattern in THREAT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)

    if not matched:
        return "none", []
    if len(matched) == 1:
        return "low", matched
    if len(matched) == 2:
        return "medium", matched
    return "high", matched


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def send_alert(comment: Comment, matched: list[str]):
    """
    Placeholder alert dispatcher.
    Replace the print statement with smtplib email or a Slack webhook call.
    """
    print("\n" + "=" * 60)
    print(f"[ALERT] Severity: {comment.severity.upper()}")
    print(f"Source : {comment.article_url}")
    print(f"Author : {comment.author}")
    print(f"Time   : {comment.timestamp}")
    print(f"Matched: {', '.join(matched)}")
    print(f"Text   : {comment.text[:300]}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    conn: AegisConnection,
    keywords: list[str] = None,
    feeds: list[str] = None,
    reddit_keyword: str = None,
    progress_cb=None,
    scan_id: Optional[int] = None,
):
    if keywords is None:
        keywords = TARGET_KEYWORDS
    if feeds is None:
        feeds = RSS_FEEDS

    log.info(f"--- Pipeline run started with keywords: {keywords} ---")

    total_articles = 0
    total_comments = 0
    total_threats = 0
    threats_high = 0
    threats_medium = 0
    threats_low = 0

    def _process_article(article: Article, get_comments_fn):
        nonlocal total_articles, total_comments, total_threats, threats_high, threats_medium, threats_low

        if is_seen(conn, article.url_hash):
            log.info(f"  Skipping already-seen: {article.url}")
            return

        total_articles += 1
        log.info(f"  Processing: {article.title}")
        if progress_cb:
            progress_cb(
                f"Fetching: {article.title[:70]}...",
                articles=total_articles,
            )

        try:
            comments = get_comments_fn()
        except Exception as e:
            log.error(f"  Comment fetch failed for {article.url}: {e}")
            comments = []

        total_comments += len(comments)
        if progress_cb:
            progress_cb(
                f"Scanning {len(comments)} comment(s) from: {article.title[:55]}...",
                articles=total_articles,
                comments=total_comments,
            )

        for comment in comments:
            severity, matched = score_comment(comment)
            # Save ALL comments for the audit trail
            save_scanned(conn, comment, article.title, severity, matched, scan_id=scan_id)
            if severity != "none":
                comment.severity = severity
                save_flagged(conn, comment, matched, scan_id=scan_id)
                send_alert(comment, matched)
                
                if severity == "high":
                    threats_high += 1
                elif severity == "medium":
                    threats_medium += 1
                elif severity == "low":
                    threats_low += 1
                
                total_threats += 1
                if progress_cb:
                    progress_cb(
                        f"⚠ Threat [{severity.upper()}] found in: {article.title[:55]}",
                        articles=total_articles,
                        comments=total_comments,
                        threats=total_threats,
                    )

        mark_seen(conn, article)

    # ── 1. Reddit search (runs FIRST — fast, guaranteed comments) ───────────
    kw = reddit_keyword or (keywords[0] if keywords else None)
    if kw:
        if progress_cb:
            progress_cb(f"Searching Reddit for '{kw}'...")
        reddit_articles = poll_reddit_search(kw, limit=15)
        log.info(f"Reddit returned {len(reddit_articles)} posts")

        for article in reddit_articles:
            def _reddit_comments(a=article):
                return fetch_reddit_comments(a.url, a.url)
            _process_article(article, _reddit_comments)

    # ── 1.5 Bluesky search ──────────────────────────────────────────────────
    if kw:
        if progress_cb:
            progress_cb(f"Searching Bluesky for '{kw}'...")
        try:
            bsky_comments = poll_bluesky_search(kw, limit=15)
            log.info(f"Bluesky returned {len(bsky_comments)} posts")
            for comment in bsky_comments:
                article = Article(
                    url=comment.article_url,
                    title=f"[Bluesky] Post by {comment.author}",
                    source="bluesky",
                    published=comment.timestamp,
                )
                _process_article(article, lambda c=comment: [c])
        except Exception as e:
            log.error(f"Bluesky pipeline integration failed: {e}")

    # ── 1.6 DuckDuckGo search ────────────────────────────────────────────────
    if kw:
        if progress_cb:
            progress_cb(f"Searching DuckDuckGo for '{kw}'...")
        try:
            ddg_articles = poll_duckduckgo_search(kw, limit=10)
            log.info(f"DuckDuckGo returned {len(ddg_articles)} pages")
            for article in ddg_articles:
                def _ddg_comments(a=article):
                    # Sleep 1 second between DuckDuckGo page fetches to be polite/prevent blocks
                    time.sleep(1)
                    html = fetch_html_static(a.url)
                    if html:
                        return extract_comments_generic(html, a.url)
                    return []
                _process_article(article, _ddg_comments)
        except Exception as e:
            log.error(f"DuckDuckGo pipeline integration failed: {e}")

    # ── 2. RSS / Google News — store articles as metadata only ──────────────
    # Major news sites disable comment sections or JS-gate them.
    # We still poll so article titles appear in the Articles panel, but we
    # do NOT attempt slow HTML fetches that would return 0 comments anyway.
    for feed_url in feeds:
        if progress_cb:
            progress_cb(f"Indexing Google News articles for '{keywords[0]}'...")
        rss_articles = poll_rss(feed_url, keywords)
        for article in rss_articles:
            if not is_seen(conn, article.url_hash):
                total_articles += 1
                mark_seen(conn, article)

        if progress_cb and rss_articles:
            progress_cb(
                f"Indexed {len(rss_articles)} news article(s) from Google News",
                articles=total_articles,
            )

    log.info("--- Pipeline run complete ---")
    return {
        "articles_found": total_articles,
        "comments_scanned": total_comments,
        "threats_high": threats_high,
        "threats_medium": threats_medium,
        "threats_low": threats_low,
    }



def main():
    conn = init_db()
    log.info(f"Database ready at {DB_PATH}")
    log.info(f"Monitoring {len(RSS_FEEDS)} feed(s), polling every {POLL_INTERVAL_SECONDS}s")

    while True:
        run_pipeline(conn)
        log.info(f"Sleeping {POLL_INTERVAL_SECONDS}s until next poll...")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
