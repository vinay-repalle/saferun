"""`saferun cleanup`: list what SafeRun left behind and remove it after confirmation.

What it looks for, and nothing else:
  * old SafeRun analyzer images: label saferun.analyzer=1 and not the current one. The guards in sandbox/oldimages.py are checked again
    right before each delete; the current analyzer image, the python sandbox image and images without that label are never touched;
  * OSV data of ecosystems SafeRun no longer supports (npm), as recorded in its own manifest (osvdb.prune_unsupported);
  * containers and temporary workspaces abandoned by a crashed run (sandbox/reaper.py: expired deadline label, unlocked workspace);
  * `analyzer-image-id.bak` next to the analyzer lock (a hand-made backup SafeRun never uses), only a regular file of the current user.
On a terminal it lists, then asks (default: no). Without a terminal it only lists, unless --yes.
Exit status: 0 = nothing to do, listed only, or everything removed; 1 = something could not be checked or removed.
"""
from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from . import dockerdiag, hostos, ui
from .engine import osvdb
from .engine.model import clean_text
from .sandbox import SandboxError
from .sandbox import analyzer as sa
from .sandbox import oldimages
from .sandbox.reaper import reap_orphans

IMAGE, OSV, CONTAINER, WORKSPACE, BACKUP = "analyzer image", "OSV data", "container", "workspace", "lock backup"
NEVER = "Never touched: the current analyzer image, the python sandbox image, and any image without the saferun.analyzer label."


@dataclass(frozen=True)
class Item:
    kind: str
    name: str            # image ID, ecosystem, container/workspace name or file path
    size: int | None
    why: str             # what it is (for a removable item) or why it is kept


def _backup_item(p: Path) -> tuple[Item | None, Item | None]:
    """(removable item, kept item) for the lock backup; both None when there is no such file."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        return None, Item(BACKUP, str(p), None, f"cannot be examined: {e}")
    if not stat.S_ISREG(st.st_mode):
        return None, Item(BACKUP, str(p), None, "not a regular file (a symlink?); left alone")
    mine = hostos.owned_by_current_user(p) if hostos.IS_WINDOWS else st.st_uid == os.geteuid()
    if not mine:
        return None, Item(BACKUP, str(p), st.st_size, "not owned by the current user; left alone")
    return Item(BACKUP, str(p), st.st_size, "hand-made backup of an old analyzer lock; SafeRun does not use it"), None


class Cleanup:
    """All side effects go through injectable callables so the command is testable without Docker or the real data directory."""

    def __init__(self, *, out=None, ask=input, interactive=False, theme=None, osv_dir=None, diagnose=None, find_images=None,
                 remove_image=None, reap=None, backup_path=None, unsupported=None, prune=None):
        self.out, self.ask, self.interactive = out or sys.stdout, ask, interactive
        self.th = theme or ui.PLAIN
        self.osv_dir = Path(osv_dir) if osv_dir else osvdb.default_dir()
        self.diagnose = diagnose or dockerdiag.diagnose
        self.find_images = find_images or oldimages.find_old_images
        self.remove_image = remove_image or oldimages.remove_old_image
        self.reap = reap or reap_orphans
        self.backup_path = Path(backup_path) if backup_path else sa.lock_backup_path()
        self.unsupported = unsupported or osvdb.unsupported_data
        self.prune = prune or osvdb.prune_unsupported

    def say(self, text: str = "") -> None:
        self.out.write(text + "\n")
        self.out.flush()

    def collect(self) -> tuple[list[Item], list[Item], list[str]]:
        """(removable items, items kept with the reason, things that could not be checked). Removes nothing."""
        items: list[Item] = []
        kept: list[Item] = []
        problems: list[str] = []
        d = self.diagnose()
        if d.ok:
            try:
                for img in self.find_images():
                    (kept if img.problem else items).append(Item(IMAGE, img.image_id, img.size, img.problem or "older SafeRun analyzer image, not used by any container"))
            except SandboxError as e:
                problems.append(f"old analyzer images were not checked: {e}")
        else:
            problems.append(f"Docker is unusable, so analyzer images and leftover containers were not checked: {d.message()}")
        for eco, size in self.unsupported(self.osv_dir):
            items.append(Item(OSV, eco, size, f"in {self.osv_dir}; SafeRun no longer supports this ecosystem"))
        rep = self.reap(dry_run=True)
        items += [Item(CONTAINER, n, None, "left behind by a crashed run (its deadline has passed)") for n in rep.containers]
        items += [Item(WORKSPACE, n, None, "temporary copy left behind by a crashed run") for n in rep.workspaces]
        problems += [e for e in rep.errors if d.ok or not e.startswith("could not list containers")]
        item, keep = _backup_item(self.backup_path)
        items += [item] if item else []
        kept += [keep] if keep else []
        return items, kept, problems

    def remove(self, items: list[Item]) -> list[tuple[Item, str]]:
        """Remove the listed items; returns (item, problem) per item, problem "" when it was removed."""
        out: list[tuple[Item, str]] = []
        for it in (i for i in items if i.kind == IMAGE):
            removed, why = self.remove_image(it.name)
            out.append((it, "" if removed else why or "not removed"))
        osv = [i for i in items if i.kind == OSV]
        if osv:
            removed, problems = self.prune(self.osv_dir)
            done = {eco for eco, _ in removed}
            out += [(i, "" if i.name in done else "; ".join(problems) or "not removed") for i in osv]
            out += [(Item(OSV, "", None, ""), p) for p in problems if done]     # partial problems (e.g. a folder kept) stay visible
        names = {i.name for i in items if i.kind in (CONTAINER, WORKSPACE)}
        if names:
            rep = self.reap(only=names)
            gone = set(rep.containers) | set(rep.workspaces)
            err = "; ".join(rep.errors)
            out += [(i, "" if i.name in gone else err or "no longer eligible (in use again?)") for i in items if i.kind in (CONTAINER, WORKSPACE)]
        for it in (i for i in items if i.kind == BACKUP):
            again, _ = _backup_item(Path(it.name))                     # re-checked right before the delete
            try:
                if again is None:
                    raise OSError("it changed since it was listed; left alone")
                os.unlink(it.name)
                out.append((it, ""))
            except OSError as e:
                out.append((it, str(e)))
        return out

    def _line(self, it: Item) -> str:
        size = ui.size_text(it.size)
        return f"  {it.kind:<15} {self._name(it)}" +(f"  {size}" if size else "") + self.th.paint(f"  ({clean_text(it.why, 200)})", "dim")

    def run(self, *, assume_yes: bool = False) -> int:
        p = self.th.paint
        self.say(p("SafeRun cleanup", "bold", "cyan"))
        self.say()
        items, kept, problems = self.collect()
        total = sum(i.size or 0 for i in items)
        if items:
            self.say(p(f"Found {len(items)} item(s) to remove" + (f" (about {ui.size_text(total)})" if total else "") + ":", "bold"))
            for it in items:
                self.say(self._line(it))
        else:
            self.say("Nothing to clean up.")
        if kept:
            self.say()
            self.say(p("Kept:", "bold"))
            for it in kept:
                self.say(self._line(it))
        if problems:
            self.say()
            self.say(p("Not checked:", "bold", "yellow"))
            for msg in problems:
                self.say(f"  {self.th.icons['warn']} {clean_text(msg, 400)}")
        self.say()
        self.say(p(NEVER, "dim"))
        if not items:
            return 1 if problems else 0
        if not assume_yes:
            if not self.interactive:
                self.say("Nothing was removed (not a terminal). To remove the items above: saferun cleanup --yes")
                return 1 if problems else 0
            try:
                answer = self.ask(f"Remove these {len(items)} item(s)? [y/N] ").strip().lower()
            except EOFError:
                answer = ""
            if answer not in ("y", "yes"):
                self.say("Nothing was removed.")
                return 1 if problems else 0
        self.say()
        results = self.remove(items)
        failed = 0
        for it, why in results:
            if why:
                failed += 1
                self.say(p(f"  FAILED   {it.kind} {self._name(it)}: {clean_text(why, 300)}", "red"))
            else:
                self.say(p(f"  removed  {it.kind} {self._name(it)}", "green"))
        removed = sum(1 for _, why in results if not why)
        self.say()
        self.say(f"Done: {removed} removed" + (f", {failed} problem(s)" if failed else "") + ".")
        return 1 if failed or problems else 0

    @staticmethod
    def _name(it: Item) -> str:
        return oldimages.short_id(it.name) if it.kind == IMAGE else clean_text(it.name, 120)
