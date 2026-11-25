import ast
import re
from dataclasses import dataclass
import pandas as pd


@dataclass
class ReviewFinding:
    severity: str
    category: str
    line: int
    rule_id: str
    message: str
    suggestion: str


SECRET_PATTERNS = (
    (r"(api_key|secret_key|password|token|aws_secret)\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]", "SEC-001", "Hardcoded credential or API secret detected.", "Move secrets to environment variables (`os.environ`) or GitHub Secrets."),
    (r"sk-[A-Za-z0-9]{16,}", "SEC-002", "Hardcoded LLM API token pattern (`sk-...`) exposed.", "Revoke the key immediately and load via `os.getenv(...)`."),
)


def parse_added_lines_from_diff(diff_text: str) -> tuple[str, dict[int, int]]:
    """Extracts added Python lines from a unified `git diff` and maps them to target line numbers."""
    added_code = []
    line_map = {}
    current_target_line = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("@@"):
            match = re.search(r"\+(\d+)", raw_line)
            if match:
                current_target_line = int(match.group(1)) - 1
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_target_line += 1
            clean_line = raw_line[1:]
            added_code.append(clean_line)
            line_map[len(added_code)] = current_target_line
        elif not raw_line.startswith("-"):
            current_target_line += 1

    return "\n".join(added_code), line_map


def analyze_python_code(source_code: str, line_map: dict[int, int] | None = None) -> list[ReviewFinding]:
    """Runs AST + Security + Maintainability checks on Python source code."""
    findings: list[ReviewFinding] = []
    lines = source_code.splitlines()

    def map_line(lineno: int) -> int:
        if line_map and lineno in line_map:
            return line_map[lineno]
        return lineno

    # 1. Regex Security & Hygiene Checks
    for idx, line in enumerate(lines, start=1):
        for pat, rule_id, msg, fix in SECRET_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                findings.append(ReviewFinding("CRITICAL", "Security", map_line(idx), rule_id, msg, fix))
        if re.search(r"SELECT\s+.*%s|f['\"]SELECT\s+.*\{", line, re.IGNORECASE):
            findings.append(
                ReviewFinding(
                    "CRITICAL",
                    "SQL Injection",
                    map_line(idx),
                    "SEC-003",
                    "Potential SQL injection via string formatting.",
                    "Use parameterized SQL queries (`cursor.execute('... WHERE id = ?', (val,))`).",
                )
            )
        if "print(" in line and not line.strip().startswith("#"):
            findings.append(
                ReviewFinding(
                    "LOW",
                    "Observability",
                    map_line(idx),
                    "QUAL-001",
                    "Raw `print()` statement found in production code.",
                    "Replace with structured `logging.info(...)` or OpenTelemetry spans.",
                )
            )

    # 2. Python AST Structural & Security Checks
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        # Dangerous eval / exec / shell=True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                findings.append(
                    ReviewFinding(
                        "CRITICAL",
                        "Remote Code Execution",
                        map_line(node.lineno),
                        "SEC-004",
                        f"Dangerous built-in `{node.func.id}()` enables arbitrary code execution.",
                        "Use `ast.literal_eval()` for safe data parsing or explicit dispatch tables.",
                    )
                )
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(
                        ReviewFinding(
                            "HIGH",
                            "Command Injection",
                            map_line(node.lineno),
                            "SEC-005",
                            "Subprocess invoked with `shell=True`.",
                            "Pass argument lists (`subprocess.run(['cmd', arg], shell=False)`).",
                        )
                    )

        # Bare except:
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append(
                ReviewFinding(
                    "MEDIUM",
                    "Reliability",
                    map_line(node.lineno),
                    "REL-001",
                    "Bare `except:` clause catches `SystemExit` and `KeyboardInterrupt`.",
                    "Catch specific exceptions (e.g., `except ValueError as exc:`).",
                )
            )

        # Mutable default arguments (def f(items=[]):)
        if isinstance(node, ast.FunctionDef):
            for default in node.args.defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    findings.append(
                        ReviewFinding(
                            "HIGH",
                            "Bug Risk",
                            map_line(node.lineno),
                            "BUG-001",
                            f"Mutable default argument in function `{node.name}()`.",
                            "Default to `None` and initialize inside the function body.",
                        )
                    )
            # Cyclomatic / branch complexity check
            branches = sum(
                1 for child in ast.walk(node)
                if isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.With))
            )
            if branches >= 5:
                findings.append(
                    ReviewFinding(
                        "MEDIUM",
                        "Maintainability",
                        map_line(node.lineno),
                        "COMP-001",
                        f"High branching complexity ({branches} nested blocks) in `{node.name}()`.",
                        "Decompose into smaller, unit-testable helper functions.",
                    )
                )

    return findings


def generate_pr_markdown_review(findings: list[ReviewFinding], filename: str = "pull_request.py") -> str:
    """Formats findings as an automated GitHub Pull Request review comment."""
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    verdict = "REQUEST CHANGES" if (crit > 0 or high > 0) else ("COMMENT" if findings else "APPROVE")

    header = [
        f"## Automated AI PR Code Review — `{filename}`",
        f"**Merge Verdict:** `{verdict}` | **Total Findings:** `{len(findings)}` (`{crit}` Critical, `{high}` High)\n",
    ]
    if not findings:
        header.append("No security vulnerabilities, bug risks, or maintainability regressions detected. Ready to merge!")
        return "\n".join(header)

    header.append("| Severity | Line | Rule | Issue | Recommended Fix |")
    header.append("| :--- | :---: | :---: | :--- | :--- |")
    for f in findings:
        header.append(f"| **{f.severity}** | `L{f.line}` | `{f.rule_id}` | {f.message} | {f.suggestion} |")
    return "\n".join(header)


def findings_to_dataframe(findings: list[ReviewFinding]) -> pd.DataFrame:
    if not findings:
        return pd.DataFrame(columns=("Severity", "Category", "Line", "Rule", "Message", "Suggestion"))
    return pd.DataFrame([
        {
            "Severity": f.severity,
            "Category": f.category,
            "Line": f.line,
            "Rule": f.rule_id,
            "Message": f.message,
            "Suggestion": f.suggestion,
        }
        for f in findings
    ])
