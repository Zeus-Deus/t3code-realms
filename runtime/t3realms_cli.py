"""Isolated CLI entry point: python3 -I -B runtime/t3realms_cli.py --home DIR ..."""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from t3realms.cli import main

if __name__ == '__main__':
    sys.exit(main())
