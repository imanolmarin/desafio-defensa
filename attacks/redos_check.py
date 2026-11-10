# Uso (desde comments-service/): PYTHONPATH=. .venv/bin/python ../attacks/redos_check.py
"""Bonus ReDoS: mide las regex del proyecto con entradas pensadas para forzar backtracking."""
import re, time
from app.validation import HOSTNAME, SAFE_FILENAME
from app.schemas import USERNAME_PATTERN, UserCreate
EMAIL = r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$"
def t(rx, s, n=1):
    t0=time.perf_counter(); [re.fullmatch(rx, s) if isinstance(rx,str) else rx.fullmatch(s) for _ in range(n)]; return (time.perf_counter()-t0)/n
print("Python re (backtracking):")
for n in (1000, 2000, 4000, 8000):
    evil = "a@" + "a." * n + "!"  # muchos puntos y un final que hace fallar
    print(f"  EMAIL      len={len(evil):6d}  {t(EMAIL, evil)*1000:9.2f} ms")
for n in (60, 250, 1000, 5000):
    evil = ("a" * 61 + "-.") * (n // 63 + 1) + "!"
    print(f"  HOSTNAME   len={len(evil):6d}  {t(HOSTNAME, evil)*1000:9.3f} ms")
for n in (1000, 10000):
    print(f"  FILENAME   len={n:6d}  {t(SAFE_FILENAME, 'a'*n+'.txx')*1000:9.3f} ms")
import pydantic
print("pydantic (regex de Rust, sin backtracking) con el mismo email malicioso:")
for n in (1000, 8000, 100000):
    evil = "a@" + "a." * n + "!"
    t0=time.perf_counter()
    try: UserCreate(username="abc", email=evil)
    except pydantic.ValidationError: pass
    print(f"  UserCreate.email len={len(evil):7d}  {(time.perf_counter()-t0)*1000:7.2f} ms")
