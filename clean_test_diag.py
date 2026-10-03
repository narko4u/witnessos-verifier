#!/usr/bin/env python3
"""Remove the diagnostic print left in the test file."""
from pathlib import Path
p = Path("/tmp/ver-313/tests/test_scheme_dispatch.py")
t = p.read_text(encoding="utf-8")
old = '\nprint("DIAG HAVE_CRYPTO=", HAVE_CRYPTO, "ERR=", _IMPORT_ERROR)\n'
assert old in t
t = t.replace(old, "")
t = t.replace('_IMPORT_ERROR = None\n', "").replace(
    '    _IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"\n', "")
p.write_text(t, encoding="utf-8")
print("diagnostic removed")
