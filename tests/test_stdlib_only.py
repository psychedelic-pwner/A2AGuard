import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "a2aguard"


def test_runtime_imports_are_stdlib():
    offenders = []
    for path in sorted(ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module.split(".")[0]]
            for module in modules:
                if module == "a2aguard":
                    continue
                if module not in sys.stdlib_module_names:
                    offenders.append(f"{path.name}: {module}")
    assert offenders == []
