"""Service mode — bring a web-app target up on localhost so probes can
hit the real running service (the pen-test layer).

Guardrails by construction: every published port is rewritten to a
127.0.0.1 binding before `docker compose up`, and probe containers join
only the compose network — not the open internet.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

FINDINGS = Path(__file__).resolve().parent.parent / "findings"
COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml",
                 "compose.yaml", "compose.yml")


@dataclass
class ServiceHandle:
    repo: str
    base_url: str                 # host view: http://127.0.0.1:<port>
    project: str                  # compose project name
    shared: Path                  # dir shared with probe containers
    ports: list[str] = field(default_factory=list)
    internal_base: str = ""       # in-network view probes use: http://target:<port>

    def down(self) -> None:
        subprocess.run(["docker", "compose", "-p", self.project, "down",
                        "-v", "--remove-orphans"], capture_output=True,
                       timeout=120)
        try:
            import shutil
            shutil.rmtree(self.shared, ignore_errors=True)
        except Exception:
            pass

    def run_probe(self, pdir: Path, script: str = "service-probe.sh",
                  timeout: int = 120) -> str:
        """Run /poc/<script> in a sandboxed container on the service
        network (NOT internet: compose network only). Returns output."""
        cmd = ["docker", "run", "--rm", "--memory", "1g", "--cpus", "1",
               "--pids-limit", "128",
               "--network", f"{self.project}_default",
               "-v", f"{pdir.resolve()}:/poc:rw",
               "-v", f"{self.shared.resolve()}:/shared:rw",
               "indictment-sandbox-python", "timeout", str(timeout),
               "bash", f"/poc/{script}"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout + 60)
            return r.stdout + r.stderr
        except Exception as e:
            return f"service probe runner failed: {e}"


_booted: dict[str, ServiceHandle | None] = {}
_boot_lock = threading.Lock()


def booted(repo_root: Path, out_dir: Path | None = None
           ) -> ServiceHandle | None:
    """Lazy once-per-process boot; None means not service-shaped (or boot
    failed — the reason was printed). poc workers race here — the lock
    keeps boot single-flight."""
    key = str(repo_root)
    with _boot_lock:
        if key not in _booted:
            _booted[key] = boot(repo_root, out_dir)
        return _booted[key]


def shutdown_all() -> None:
    """Tear down every compose project this process booted. Idempotent —
    safe to call from pipeline finally blocks and watch loops."""
    with _boot_lock:
        handles = [h for h in _booted.values() if h is not None]
        _booted.clear()
    for h in handles:
        try:
            h.down()
            print(f"[service] {h.repo}: down", flush=True)
        except Exception as e:
            print(f"[service] {h.repo}: down failed: {e}", flush=True)


def _rewrite_local(compose: dict) -> tuple[dict, list[str], tuple]:
    """Force every published port onto 127.0.0.1 (guardrail). Returns the
    host ports bound plus the first published service's in-network
    (service-name, container-port) pair — probes on the compose network
    address the service by NAME at its CONTAINER port, never 'target'."""
    ports: list[str] = []
    first: tuple[str, str] | None = None
    for sname, svc in (compose.get("services") or {}).items():
        ps = svc.get("ports") or []
        fixed = []
        for p in ps:
            s = str(p)
            # "8080:80" / "0.0.0.0:8080:80" -> "127.0.0.1:8080:80"
            parts = s.split(":")
            host = parts[-2] if len(parts) >= 2 else s
            ports.append(host)
            fixed.append(f"127.0.0.1:{host}:{parts[-1]}")
            if first is None:
                first = (sname, parts[-1])
        if fixed:
            svc["ports"] = fixed
    return compose, ports, first


def _wait_up(base_url: str, timeout: int = 60) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(base_url, timeout=3, follow_redirects=True)
            if r.status_code < 600:      # any HTTP answer = service up
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def boot(repo_root: Path, out_dir: Path | None = None
         ) -> ServiceHandle | None:
    name = repo_root.name
    compose_path = next((repo_root / c for c in COMPOSE_NAMES
                         if (repo_root / c).exists()), None)
    import yaml
    if compose_path is None:
        print(f"[service] {name}: no compose file — source-level PoCs only")
        return None
    try:
        compose = yaml.safe_load(compose_path.read_text()) or {}
        compose, ports, first = _rewrite_local(compose)
    except Exception as e:
        print(f"[service] {name}: unreadable compose ({e})")
        return None
    if not ports:
        print(f"[service] {name}: compose publishes no ports — skipping")
        return None
    out_dir = out_dir or FINDINGS / name
    out_dir.mkdir(parents=True, exist_ok=True)
    # write the guardrail-fixed compose next to findings, context = repo
    compose["services"] = compose.get("services") or {}
    fixed = out_dir / "compose.indictment.yml"
    compose = dict(compose)
    fixed.write_text(yaml.safe_dump(compose))
    project = f"indictment-{name}"[:60]
    shared = out_dir / "service-shared"
    shared.mkdir(exist_ok=True)
    r = subprocess.run(
        ["docker", "compose", "-p", project, "-f", str(fixed),
         "up", "-d", "--build"], capture_output=True, text=True,
        cwd=repo_root, timeout=900)
    if r.returncode != 0:
        print(f"[service] {name}: compose up failed: "
              f"{(r.stderr or r.stdout)[-300:]}")
        subprocess.run(["docker", "compose", "-p", project, "-f",
                        str(fixed), "down", "-v", "--remove-orphans"],
                       capture_output=True, timeout=120)
        return None
    base_url = f"http://127.0.0.1:{ports[0]}"
    if not _wait_up(base_url):
        print(f"[service] {name}: booted but never answered on {base_url}")
    svc_name, svc_port = first or ("target", ports[0])
    handle = ServiceHandle(repo=name, base_url=base_url, project=project,
                           shared=shared, ports=ports,
                           internal_base=f"http://{svc_name}:{svc_port}")
    print(f"[service] {name}: live at {base_url} (network "
          f"{project}_default, internal {handle.internal_base}, "
          f"localhost-only)")
    return handle


def template_boot(template_dir: Path, repo_root: Path,
                  port: str, out_dir: Path | None = None
                  ) -> ServiceHandle | None:
    """Boot from a harness-provided template (service/templates/<name>)
    instead of a repo-own compose — used for first-class targets like
    snare. The image is pre-built with `docker build -f <template
    Dockerfile> <clone>` (the -f file may live outside the context), the
    generated compose references the image, and the shared volume points
    into findings/. Ports are localhost-bound in the template."""
    name = repo_root.name
    out_dir = out_dir or FINDINGS / name
    out_dir.mkdir(parents=True, exist_ok=True)
    shared = out_dir / "service-shared"
    shared.mkdir(exist_ok=True)
    # snare drops to 'nobody' before running per-repo programs — the exec
    # log must be writable by that uid
    os.chmod(shared, 0o777)
    project = f"indictment-{name}"[:60]
    image = f"indictment-svc-{name}"[:60]
    b = subprocess.run(
        ["docker", "build", "-f", str((template_dir / "Dockerfile").resolve()),
         "-t", image, str(repo_root.resolve())],
        capture_output=True, text=True, timeout=1800)
    if b.returncode != 0:
        print(f"[service] {name}: image build failed: "
              f"{(b.stderr or b.stdout)[-400:]}")
        return None
    raw = (template_dir / "docker-compose.yml").read_text()
    raw = raw.replace("indictment-svc-__NAME__", image)
    raw = raw.replace("PLACEHOLDER_SHARED", str(shared.resolve()))
    fixed = out_dir / "compose.indictment.yml"
    fixed.write_text(raw)
    # marker: tells indictment.httpprobes this service carries the webhook-exec
    # template shape (shared exec log at /shared)
    (shared / "webhook-template").write_text("snare webhook template")
    r = subprocess.run(
        ["docker", "compose", "-p", project, "-f", str(fixed),
         "up", "-d"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"[service] {name}: template boot failed: "
              f"{(r.stderr or r.stdout)[-400:]}")
        return None
    base_url = f"http://127.0.0.1:{port}"
    if not _wait_up(base_url):
        print(f"[service] {name}: booted but never answered on {base_url}")
    print(f"[service] {name}: live at {base_url} (template, localhost-only)")
    return ServiceHandle(repo=name, base_url=base_url, project=project,
                         shared=shared, ports=[port],
                         internal_base=f"http://target:{port}")
