#!/usr/bin/env python3
"""Raise the cryptography floor to the version that provides ML-DSA."""
from pathlib import Path
p = Path("/tmp/ver-313/pyproject.toml")
t = p.read_text(encoding="utf-8")
n = t.count('"cryptography>=43.0"')
assert n == 2, f"expected 2 cryptography pins, found {n}"
t = t.replace('"cryptography>=43.0"', '"cryptography>=50.0"')
p.write_text(t, encoding="utf-8")
print("floor raised on", n, "lines")
