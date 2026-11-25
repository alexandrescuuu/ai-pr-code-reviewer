import os
import subprocess
import sys
import urllib.request
import json
from reviewer import parse_added_lines_from_diff, analyze_python_code, generate_pr_markdown_review


def get_git_diff() -> str:
    try:
        out = subprocess.check_output(["git", "diff", "HEAD~1", "HEAD", "--", "*.py"], text=True, stderr=subprocess.DEVNULL)
        return out
    except Exception:
        return ""


def post_github_pr_comment(body: str) -> None:
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")
    pr_number = os.getenv("PR_NUMBER")
    if not (token and repo and pr_number):
        return

    url = f"https://github.com{repo}/issues/{pr_number}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(f"Posted PR review comment (HTTP {resp.status}).")


def main() -> int:
    diff_text = get_git_diff()
    if not diff_text.strip():
        print("No Python diff detected in HEAD commit.")
        return 0

    added_code, line_map = parse_added_lines_from_diff(diff_text)
    findings = analyze_python_code(added_code, line_map=line_map)
    review_md = generate_pr_markdown_review(findings, filename="PR Diff (*.py)")
    print(review_md)

    post_github_pr_comment(review_md)
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    return 1 if critical_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
