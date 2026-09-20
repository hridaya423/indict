"""Recon stage — repo inventory + LLM threat model (attacker-forward)."""
from __future__ import annotations

import json
from pathlib import Path

from .llms import Client
from .util import detect_languages, prompt

MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.py", "package.json",
             "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle",
             "composer.json", "mix.exs"}
ENTRY_HINTS = ("main", "app", "server", "index", "cli", "route", "handler",
               "api", "cmd", "__main__", "manage")


def inventory(root: Path) -> dict:
    files = [p for p in root.rglob("*") if p.is_file()
             and ".git" not in p.parts and "node_modules" not in p.parts]
    langs = detect_languages(root)
    manifests = [f.name for f in files if f.name in MANIFESTS]
    entries = [str(f.relative_to(root)) for f in files
               if any(h in f.stem.lower() for h in ENTRY_HINTS)][:50]
    readme = ""
    for f in files:
        if f.name.lower().startswith("readme"):
            readme = f.read_text(errors="replace")[:6000]
            break
    return {"languages": langs, "manifests": manifests,
            "entrypoints": entries, "readme": readme,
            "file_count": len(files)}


def threat_model(client: Client | None, root: Path, inv: dict) -> dict:
    if client is None:
        return {}
    user = prompt("threatmodel",
                  languages=json.dumps(inv["languages"]),
                  manifests=", ".join(inv["manifests"]),
                  entrypoints="\n".join(inv["entrypoints"][:30]),
                  readme=inv["readme"])
    r = client.chat("triage", [
        {"role": "system", "content":
         "You are a security auditor building a threat model for an "
         "authorized audit of an open-source project."},
        {"role": "user", "content": user}], expect_json=True)
    return r.parsed or {}
