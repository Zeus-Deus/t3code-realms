"""Explicit-home native runtime for T3 Code Realms."""
import sys

# Defense in depth for callers importing the package without the CLI's -B.
sys.dont_write_bytecode = True
