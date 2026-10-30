"""Kernel-view attestation: run a tiny probe inside a sandbox built exactly like a scan sandbox
and report what the *kernel* says is in force (not what we asked Docker for).

Language-agnostic: the probe is POSIX sh reading /proc and /sys, so it works in any image that
meets the profile requirements. Controls that cannot be read are reported "unverified" or
"unavailable"; nothing is reported "verified" without evidence.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass, field

from . import docker as dk
from .config import DEFAULT_IMAGE, SANDBOX_UID, ControlStatus, SandboxError, SandboxLimits
from .controls import MIB
from .runner import run_sandboxed

PROBE = r"""
echo "uid=$(id -u)"
sed -n 's/^\(NoNewPrivs\|Seccomp\|CapEff\|CapBnd\|CapAmb\):[[:space:]]*/\1=/p' /proc/self/status
echo "apparmor=$(cat /proc/self/attr/current 2>/dev/null || echo none)"
for f in memory.max memory.swap.max pids.max cpu.max; do echo "$f=$(cat /sys/fs/cgroup/$f 2>/dev/null || echo none)"; done
echo "ifaces=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ',')"
for p in /workspace/.w /.w /tmp/.w; do if ( : > "$p" ) 2>/dev/null; then echo "write:$p=yes"; else echo "write:$p=no"; fi; done
"""


@dataclass
class AttestationReport:
    image: str
    image_id: str
    controls: list[ControlStatus] = field(default_factory=list)

    def by_name(self) -> dict[str, ControlStatus]:
        return {c.name: c for c in self.controls}

    @property
    def violated(self) -> list[ControlStatus]:
        return [c for c in self.controls if c.state == "violated"]

    @property
    def ok(self) -> bool:
        """No control observed to be violated (unverified/unavailable ones are listed, not hidden)."""
        return not self.violated


def _parse(out: str) -> dict[str, str]:
    kv = {}
    for line in out.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            kv[k.strip()] = v.strip()
    return kv


def evaluate(kv: dict[str, str], lim: SandboxLimits, daemon_has_apparmor: bool) -> list[ControlStatus]:
    """Turn raw probe output into control statuses (pure; unit-tested)."""
    def st(name, ok, detail, missing=False):
        return ControlStatus(name, "unverified" if missing else ("verified" if ok else "violated"), detail)

    def need(key):
        return key not in kv or kv[key] == "none"

    caps = (kv.get("CapEff"), kv.get("CapBnd"), kv.get("CapAmb"))
    apparmor = kv.get("apparmor", "none")
    out = [
        st("kernel-non-root", kv.get("uid") == str(SANDBOX_UID), f"uid={kv.get('uid')}", missing="uid" not in kv),
        st("kernel-no-new-privileges", kv.get("NoNewPrivs") == "1", f"NoNewPrivs={kv.get('NoNewPrivs')}",
           missing="NoNewPrivs" not in kv),
        st("kernel-seccomp-filter", kv.get("Seccomp") == "2", f"Seccomp={kv.get('Seccomp')} (2 = filter)",
           missing="Seccomp" not in kv),
        st("kernel-capabilities-empty", all(c == "0" * 16 for c in caps if c is not None) and None not in caps[:2],
           f"CapEff={caps[0]} CapBnd={caps[1]} CapAmb={caps[2]}", missing=caps[0] is None or caps[1] is None),
        st("kernel-network-loopback-only", kv.get("ifaces") == "lo,", f"interfaces={kv.get('ifaces')!r}",
           missing="ifaces" not in kv),
        st("kernel-memory-max", kv.get("memory.max") == str(lim.memory_mb * MIB), f"memory.max={kv.get('memory.max')}",
           missing=need("memory.max")),
        st("kernel-swap-disabled", kv.get("memory.swap.max") == "0", f"memory.swap.max={kv.get('memory.swap.max')}",
           missing=need("memory.swap.max")),
        st("kernel-pids-max", kv.get("pids.max") == str(lim.pids), f"pids.max={kv.get('pids.max')}",
           missing=need("pids.max")),
        st("kernel-cpu-quota", (kv.get("cpu.max") or "").split()[:1] == [str(int(lim.cpus * 100_000))],
           f"cpu.max={kv.get('cpu.max')}", missing=need("cpu.max")),
        st("fs-workspace-read-only", kv.get("write:/workspace/.w") == "no", f"write={kv.get('write:/workspace/.w')}",
           missing="write:/workspace/.w" not in kv),
        st("fs-root-read-only", kv.get("write:/.w") == "no", f"write={kv.get('write:/.w')}",
           missing="write:/.w" not in kv),
        st("fs-tmp-writable", kv.get("write:/tmp/.w") == "yes", f"write={kv.get('write:/tmp/.w')}",
           missing="write:/tmp/.w" not in kv),
    ]
    if apparmor.startswith("docker-default") and "(enforce)" in apparmor:
        out.append(ControlStatus("kernel-apparmor-profile", "verified", apparmor))
    elif apparmor in ("none", "") or not daemon_has_apparmor:
        out.append(ControlStatus("kernel-apparmor-profile", "unavailable",
                                 "AppArmor not active for the container on this host (not required)"))
    else:
        out.append(ControlStatus("kernel-apparmor-profile", "violated", f"profile={apparmor!r}"))
    return out


def attest(image: str = DEFAULT_IMAGE, limits: SandboxLimits | None = None) -> AttestationReport:
    """Probe the sandbox for `image`. Costs one short container run."""
    lim = limits or SandboxLimits(timeout_s=20)
    with tempfile.TemporaryDirectory(prefix="saferun-attest-") as empty:
        r = run_sandboxed(empty, ["sh", "-c", PROBE], lim, image=image)
    if r.exit_code != 0:
        raise SandboxError(f"attestation probe failed (exit {r.exit_code}): {r.stderr.strip()[:300]}")
    daemon_apparmor = any(c.name == "daemon-apparmor" and c.state == "verified" for c in r.controls)
    probe_controls = evaluate(_parse(r.stdout), lim, daemon_apparmor)
    return AttestationReport(image, r.image_id, [*r.controls, *probe_controls])
