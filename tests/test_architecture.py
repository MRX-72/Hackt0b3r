"""R-PRC-002: fails if any raven module imports another that diagram 05 does not allow."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIAGRAM = ROOT / "docs/diagrams/05-module-dependencies.mmd"
EDGE = re.compile(r"^\s*(\w+)\s*-->\s*(\w+)\s*$")


def allowed_edges() -> set[tuple[str, str]]:
    return {m.groups() for line in DIAGRAM.read_text().splitlines() if (m := EDGE.match(line))}  # type: ignore[misc]


def imported_raven_modules(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            parts = node.module.split(".")
            if parts[0] == "raven":
                found.add(parts[1] if len(parts) > 1 else "")
                if len(parts) == 1:
                    found.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            found.update(a.name.split(".")[1] for a in node.names if a.name.startswith("raven."))
    return found - {""}


def test_every_package_is_in_the_diagram() -> None:
    packages = {p.name for p in (ROOT / "raven").iterdir() if (p / "__init__.py").exists()}
    in_diagram = {n for edge in allowed_edges() for n in edge} | {"contracts"}
    assert packages <= in_diagram, (
        f"packages missing from diagram 05: {sorted(packages - in_diagram)}"
    )


def test_imports_follow_diagram_direction() -> None:
    allowed = allowed_edges()
    violations = []
    for path in (ROOT / "raven").rglob("*.py"):
        owner = path.relative_to(ROOT / "raven").parts[0]
        if owner.endswith(".py"):
            continue
        violations += [
            f"{path.relative_to(ROOT)}: {owner} -> {dep}"
            for dep in imported_raven_modules(path)
            if dep != owner and (owner, dep) not in allowed
        ]
    assert not violations, "\n".join(violations)


def test_checker_detects_a_violation(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("from raven.api import server\n")
    assert imported_raven_modules(bad) == {"api"}
    assert ("ml", "api") not in allowed_edges()
