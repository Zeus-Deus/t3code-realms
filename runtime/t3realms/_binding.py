"""Load only this immutable T3 runtime, without host packages or home defaults."""
import importlib
from pathlib import Path
import sys
sys.dont_write_bytecode = True


def load_runtime(module=None):
    root = str(Path(__file__).resolve().parents[1])
    if root not in sys.path: sys.path.insert(0, root)
    return importlib.import_module('t3realms' + ('.' + module if module else ''))
