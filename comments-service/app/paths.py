from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR.parent / "data"
FILES_DIR = DATA_DIR / "files"
TEMPLATES_DIR = APP_DIR / "templates"
