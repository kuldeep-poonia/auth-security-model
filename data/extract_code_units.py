import os
import re
import sys
from typing import List, Optional, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

HUNK_HEADER_REGEX = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")


def parse_diff_hunks(diff_text: str) -> List[dict]:
    """Parse unified diff text into structured hunks containing modified lines."""
    lines = diff_text.splitlines()
    hunks = []
    current_hunk = None

    for line in lines:
        match = HUNK_HEADER_REGEX.match(line)
        if match:
            if current_hunk:
                hunks.append(current_hunk)
            current_hunk = {
                "header": line,
                "context_hint": match.group(3).strip(),
                "before_lines": [],
                "after_lines": [],
                "added_lines": [],
                "deleted_lines": [],
            }
            continue

        if current_hunk is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current_hunk["after_lines"].append(line[1:])
            current_hunk["added_lines"].append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            current_hunk["before_lines"].append(line[1:])
            current_hunk["deleted_lines"].append(line[1:])
        elif line.startswith(" ") or line == "":
            raw_content = line[1:] if line.startswith(" ") else line
            current_hunk["before_lines"].append(raw_content)
            current_hunk["after_lines"].append(raw_content)

    if current_hunk:
        hunks.append(current_hunk)

    return hunks


def is_noise_diff(hunk: dict) -> bool:
    """Detect if hunk changes are purely non-functional noise (imports only, comments, formatting)."""
    added = [l.strip() for l in hunk["added_lines"] if l.strip()]
    deleted = [l.strip() for l in hunk["deleted_lines"] if l.strip()]

    if not added and not deleted:
        return True

    # Check if changes are only import statements
    import_keywords = ("import ", "from ", "require(", "include ", "use ", "#include")
    all_added_imports = all(l.startswith(import_keywords) for l in added)
    all_deleted_imports = all(l.startswith(import_keywords) for l in deleted)
    if all_added_imports and all_deleted_imports:
        return True

    # Check if changes are only comments
    comment_markers = ("//", "/*", "*/", "*", "#", "<!--", "--")
    all_added_comments = all(l.startswith(comment_markers) for l in added)
    all_deleted_comments = all(l.startswith(comment_markers) for l in deleted)
    if all_added_comments and all_deleted_comments:
        return True

    return False


def extract_code_units_from_diff(raw_diff: str, max_chars: int = 4000) -> Optional[Tuple[str, str]]:
    """Extract clean (before_code, after_code) pair from a raw unified diff, stripping noise.
    
    Returns:
        (before_code_unit, after_code_unit) or None if diff is empty or pure noise.
    """
    hunks = parse_diff_hunks(raw_diff)
    meaningful_hunks = [h for h in hunks if not is_noise_diff(h)]

    if not meaningful_hunks:
        return None

    before_blocks = []
    after_blocks = []

    for h in meaningful_hunks:
        before_text = "\n".join(h["before_lines"]).strip()
        after_text = "\n".join(h["after_lines"]).strip()
        if before_text:
            before_blocks.append(before_text)
        if after_text:
            after_blocks.append(after_text)

    combined_before = "\n\n".join(before_blocks).strip()
    combined_after = "\n\n".join(after_blocks).strip()

    if not combined_before or not combined_after:
        return None

    # Verify meaningful functional difference
    if combined_before == combined_after:
        return None

    # Truncate if snippet exceeds max context window limits
    if len(combined_before) > max_chars:
        combined_before = combined_before[:max_chars]
    if len(combined_after) > max_chars:
        combined_after = combined_after[:max_chars]

    return combined_before, combined_after
