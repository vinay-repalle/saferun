"""Evidence about which security controls are really in force.

Pure functions over data Docker reports, so every rule is unit-testable without a daemon.
- daemon_controls():       what the *daemon* can enforce (seccomp, cgroup limits, AppArmor)
- verify_applied_config(): what Docker *applied* to the created, not yet started, container
A control is only ever reported "verified" when this evidence supports it.
"""
from __future__ import annotations

from .config import CONTAINER_LABEL, SANDBOX_UID, ControlStatus, SandboxLimits

MIB = 1024 * 1024
# Controls without which a run is refused (unless the caller explicitly allows degradation).
REQUIRED_DAEMON = ("daemon-seccomp", "daemon-memory-limit", "daemon-swap-limit",
                   "daemon-pids-limit", "daemon-cpu-quota")


def _flag(info: dict, key: str, name: str, what: str) -> ControlStatus:
    v = info.get(key)
    if v is True:
        return ControlStatus(name, "verified", f"daemon reports {what} support")
    if v is False:
        return ControlStatus(name, "unavailable", f"daemon reports no {what} support")
    return ControlStatus(name, "unverified", f"daemon did not report {key}")


def daemon_controls(info: dict) -> list[ControlStatus]:
    """Capabilities of the Docker daemon, from `docker info`."""
    opts = [o for o in (info.get("SecurityOptions") or []) if isinstance(o, str)]
    seccomp = next((o for o in opts if o.startswith("name=seccomp")), None)
    apparmor = next((o for o in opts if o.startswith("name=apparmor")), None)
    out = []
    if seccomp is None:
        out.append(ControlStatus("daemon-seccomp", "unavailable", "daemon reports no seccomp support"))
    elif "profile=unconfined" in seccomp:
        out.append(ControlStatus("daemon-seccomp", "violated", "daemon default seccomp profile is unconfined"))
    else:
        out.append(ControlStatus("daemon-seccomp", "verified", seccomp))
    out.append(ControlStatus("daemon-apparmor", "verified", apparmor) if apparmor else
               ControlStatus("daemon-apparmor", "unavailable", "AppArmor is not enabled on this host (not required)"))
    out += [
        _flag(info, "MemoryLimit", "daemon-memory-limit", "memory limit"),
        _flag(info, "SwapLimit", "daemon-swap-limit", "swap limit"),
        _flag(info, "PidsLimit", "daemon-pids-limit", "pids limit"),
        _flag(info, "CpuCfsQuota", "daemon-cpu-quota", "CPU quota"),
    ]
    return out


def verify_applied_config(info: dict, lim: SandboxLimits, image_id: str,
                          extra_mount_targets: tuple[str, ...] = ()) -> list[ControlStatus]:
    """Check the container Docker created (from `docker inspect`) against policy."""
    hc = info.get("HostConfig") or {}
    cfg = info.get("Config") or {}
    ulimits = {u.get("Name"): (u.get("Soft"), u.get("Hard")) for u in (hc.get("Ulimits") or [])
               if isinstance(u, dict)}
    tmpfs = (hc.get("Tmpfs") or {}).get("/tmp", "")
    mounts = hc.get("Mounts") or []
    secopt = " ".join(hc.get("SecurityOpt") or [])
    nofile, fsize = lim.nofile, lim.fsize_mb * MIB

    checks = [
        ("not-privileged", hc.get("Privileged") is False, f"Privileged={hc.get('Privileged')}"),
        ("network-none", hc.get("NetworkMode") == "none", f"NetworkMode={hc.get('NetworkMode')}"),
        ("rootfs-read-only", hc.get("ReadonlyRootfs") is True, f"ReadonlyRootfs={hc.get('ReadonlyRootfs')}"),
        ("capabilities-dropped", hc.get("CapDrop") == ["ALL"] and not hc.get("CapAdd"),
         f"CapDrop={hc.get('CapDrop')} CapAdd={hc.get('CapAdd')}"),
        ("no-new-privileges", "no-new-privileges" in secopt, f"SecurityOpt={hc.get('SecurityOpt')}"),
        ("no-unconfined-profile", "unconfined" not in secopt, f"SecurityOpt={hc.get('SecurityOpt')}"),
        ("entrypoint-reset", cfg.get("Entrypoint") in (None, [], [""]), f"Entrypoint={cfg.get('Entrypoint')}"),
        ("non-root-user", cfg.get("User") == f"{SANDBOX_UID}:{SANDBOX_UID}", f"User={cfg.get('User')}"),
        ("memory-limit", hc.get("Memory") == lim.memory_mb * MIB, f"Memory={hc.get('Memory')}"),
        ("swap-disabled", hc.get("MemorySwap") == hc.get("Memory") == lim.memory_mb * MIB,
         f"Memory={hc.get('Memory')} MemorySwap={hc.get('MemorySwap')}"),
        ("cpu-quota", hc.get("NanoCpus") == int(lim.cpus * 1_000_000_000), f"NanoCpus={hc.get('NanoCpus')}"),
        ("pids-limit", hc.get("PidsLimit") == lim.pids, f"PidsLimit={hc.get('PidsLimit')}"),
        ("fd-limit", ulimits.get("nofile") == (nofile, nofile), f"nofile={ulimits.get('nofile')}"),
        ("file-size-limit", ulimits.get("fsize") == (fsize, fsize), f"fsize={ulimits.get('fsize')}"),
        ("core-dumps-off", ulimits.get("core") == (0, 0), f"core={ulimits.get('core')}"),
        ("tmp-tmpfs", all(f in tmpfs.split(",") for f in ("noexec", "nosuid", "nodev", f"size={lim.tmpfs_mb}m")),
         f"/tmp={tmpfs!r}"),
        ("shm-limit", hc.get("ShmSize") == lim.shm_mb * MIB, f"ShmSize={hc.get('ShmSize')}"),
        ("workspace-mount-read-only",
         len(mounts) == 1 + len(extra_mount_targets) and not hc.get("Binds")
         and all(isinstance(m, dict) and m.get("Type") == "bind" and m.get("ReadOnly") is True for m in mounts)
         and sorted(str(m.get("Target")) for m in mounts if isinstance(m, dict)) == sorted(("/workspace", *extra_mount_targets)),
         f"Mounts={mounts} Binds={hc.get('Binds')} expected targets={['/workspace', *extra_mount_targets]}"),
        ("no-image-volumes", not cfg.get("Volumes"), f"image declares VOLUME: {cfg.get('Volumes')}"),
        ("no-devices", not hc.get("Devices"), f"Devices={hc.get('Devices')}"),
        ("no-published-ports", not hc.get("PortBindings") and hc.get("PublishAllPorts") is False,
         f"PortBindings={hc.get('PortBindings')}"),
        ("private-namespaces", hc.get("PidMode") == "" and hc.get("IpcMode") in ("", "private")
         and hc.get("UsernsMode") == "" and hc.get("UTSMode") == "",
         f"Pid={hc.get('PidMode')!r} Ipc={hc.get('IpcMode')!r} Userns={hc.get('UsernsMode')!r} UTS={hc.get('UTSMode')!r}"),
        ("init-process", hc.get("Init") is True, f"Init={hc.get('Init')}"),
        ("logging-off", (hc.get("LogConfig") or {}).get("Type") == "none", f"LogConfig={hc.get('LogConfig')}"),
        ("oom-kill-enabled", not hc.get("OomKillDisable"), f"OomKillDisable={hc.get('OomKillDisable')}"),
        ("no-restart", (hc.get("RestartPolicy") or {}).get("Name") in ("", "no"),
         f"RestartPolicy={hc.get('RestartPolicy')}"),
        ("created-from-resolved-image", info.get("Image") == image_id, f"Image={info.get('Image')}"),
        ("saferun-label", (cfg.get("Labels") or {}).get(CONTAINER_LABEL.split("=")[0]) == "1",
         "label saferun.sandbox"),
    ]
    return [ControlStatus(n, "verified" if ok else "violated", d) for n, ok, d in checks]
