"""Pluggable discovery engines — each emits Finding candidates to the store."""
from . import sweep, hunter, taintgen, explorer, variant, fuzzlite

REGISTRY = {
    "sweep": sweep,
    "hunter": hunter,
    "taintgen": taintgen,
    "explorer": explorer,
    "variant": variant,
    "fuzzlite": fuzzlite,
}
