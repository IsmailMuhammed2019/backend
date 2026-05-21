"""
view_results.py — CLI viewer for flagged threat comments

Run:
    python view_results.py              # show all flags
    python view_results.py --severity high
    python view_results.py --limit 20
"""

import argparse
from db import get_db_connection

def view(severity: str = None, limit: int = 50):
    conn = get_db_connection()


    query = "SELECT * FROM flagged_comments"
    params = []

    if severity:
        query += " WHERE severity = ?"
        params.append(severity)

    query += " ORDER BY flagged_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()

    if not rows:
        print("No flagged comments found.")
        return

    print(f"\n{'='*70}")
    print(f"  Flagged comments — {len(rows)} result(s)")
    print(f"{'='*70}\n")

    for row in rows:
        sev = row["severity"].upper()
        label = {"HIGH": "!! HIGH", "MEDIUM": "  MED ", "LOW": "  LOW "}.get(sev, sev)
        print(f"[{label}]  {row['flagged_at']}")
        print(f"  Article : {row['article_url']}")
        print(f"  Author  : {row['author']}")
        print(f"  Matched : {row['matched_patterns']}")
        print(f"  Comment : {row['comment_text'][:250]}")
        print()

    # Summary stats
    stats = conn.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM flagged_comments
        GROUP BY severity
        ORDER BY cnt DESC
    """).fetchall()

    print(f"{'─'*40}")
    print("Summary by severity:")
    for s in stats:
        print(f"  {s['severity']:10s}  {s['cnt']}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="View threat monitor results")
    parser.add_argument("--severity", choices=["high", "medium", "low"], help="Filter by severity")
    parser.add_argument("--limit", type=int, default=50, help="Max rows to show")
    args = parser.parse_args()

    view(severity=args.severity, limit=args.limit)
