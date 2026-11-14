from pathlib import Path

import phantom_redteam

ROOT = Path(__file__).resolve().parent.parent
OLD_NAME = "kes" + "trel"
OLD_CANARY = "KST" + "RL"


def test_no_old_name_left():
    targets = [ROOT / "src", ROOT / "tests", ROOT / "examples", ROOT / "scripts", ROOT / ".github"]
    files = [ROOT / "README.md", ROOT / "pyproject.toml"]
    for base in targets:
        files.extend(p for p in base.rglob("*") if p.is_file() and "__pycache__" not in p.parts)
    offenders = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        if OLD_NAME in text or OLD_CANARY.lower() in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
    assert phantom_redteam.__version__ == "0.2.0"
