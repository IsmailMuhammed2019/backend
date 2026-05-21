"""
site_extractors.py — Custom per-site comment extractors

Drop these into scraper.py by adding a dispatch map in extract_comments_generic().
Each extractor is tailored to a site's actual HTML structure.

Usage in scraper.py:
    from site_extractors import get_extractor
    extractor = get_extractor(article.url)
    comments = extractor(html, article.url)
"""

import re
from bs4 import BeautifulSoup
from scraper import Comment
import logging

log = logging.getLogger(__name__)


def extract_bbc(html: str, article_url: str) -> list[Comment]:
    """
    BBC News — comments appear in a paginated section.
    BBC has largely disabled comments; this targets pages that still have them.
    """
    soup = BeautifulSoup(html, "html.parser")
    comments = []

    for block in soup.find_all("div", class_=re.compile(r"comment__body|sp_message")):
        text = block.get_text(separator=" ", strip=True)
        if len(text) < 10:
            continue
        comments.append(Comment(
            article_url=article_url,
            author="unknown",
            text=text,
            timestamp=None,
        ))
    return comments


def extract_wordpress(html: str, article_url: str) -> list[Comment]:
    """
    WordPress sites — standard comment structure used by millions of blogs.
    Works for any default WordPress theme.
    """
    soup = BeautifulSoup(html, "html.parser")
    comments = []

    # WordPress wraps each comment in <li class="comment"> or <article class="comment">
    for block in soup.find_all(["li", "article"], class_=re.compile(r"\bcomment\b")):
        # Author
        author_el = (
            block.find(class_="comment-author")
            or block.find(class_="fn")
            or block.find("cite")
        )
        author = author_el.get_text(strip=True) if author_el else "unknown"

        # Timestamp
        time_el = block.find("time")
        timestamp = time_el.get("datetime") if time_el else None

        # Body — .comment-body or .comment-content
        body_el = block.find(class_=re.compile(r"comment-body|comment-content"))
        if not body_el:
            continue
        text = body_el.get_text(separator=" ", strip=True)
        if len(text) < 10:
            continue

        comments.append(Comment(
            article_url=article_url,
            author=author,
            text=text,
            timestamp=timestamp,
        ))

    log.info(f"  [WordPress] {len(comments)} comment(s) from {article_url}")
    return comments


def extract_disqus_static(html: str, article_url: str) -> list[Comment]:
    """
    Disqus — the embedded iframe version requires a full browser (Playwright).
    This extractor handles the rare case where Disqus data is server-side rendered.

    For most sites: use fetch_html_dynamic() first, then parse the resulting HTML
    which will contain the rendered Disqus iframe content as plain text nodes.
    """
    soup = BeautifulSoup(html, "html.parser")
    comments = []

    # Disqus server-side rendered posts use .post-message class
    for block in soup.find_all(class_="post-message"):
        text = block.get_text(separator=" ", strip=True)
        if len(text) < 10:
            continue

        parent = block.find_parent(class_=re.compile(r"post|comment"))
        author_el = parent.find(class_=re.compile(r"author|name")) if parent else None
        author = author_el.get_text(strip=True) if author_el else "unknown"

        comments.append(Comment(
            article_url=article_url,
            author=author,
            text=text,
            timestamp=None,
        ))

    return comments


def extract_youtube_comments(html: str, article_url: str) -> list[Comment]:
    """
    YouTube — comments require dynamic rendering (Playwright + scroll).
    This is a placeholder; full YouTube support needs the YouTube Data API
    or a scroll-and-wait Playwright script.
    """
    log.warning("YouTube comment extraction requires dynamic Playwright scroll — not implemented in Phase 1")
    return []


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

EXTRACTOR_MAP = {
    "bbc.co.uk": extract_bbc,
    "bbc.com": extract_bbc,
    "wordpress": extract_wordpress,   # matched by keyword in URL
    "youtube.com": extract_youtube_comments,
}


def get_extractor(url: str):
    """Return the best extractor for a given URL, or the generic fallback."""
    from scraper import extract_comments_generic

    for key, fn in EXTRACTOR_MAP.items():
        if key in url:
            return fn

    # Check if the page uses WordPress by inspecting the HTML later;
    # for now, default to generic.
    return extract_comments_generic
