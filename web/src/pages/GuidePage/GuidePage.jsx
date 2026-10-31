import { CommandBlock } from '../../components/CommandBlock/CommandBlock'
import { useEffect, useState } from 'react'
import { Mark } from '../../components/Mark/Mark'
import { SiteFooter } from '../../components/SiteFooter/SiteFooter'
import { SiteNav } from '../../components/SiteNav/SiteNav'
import { DOCS, HONEST_LIMITS, PLATFORMS, REQUIREMENTS, SAFETY, STEPS, TRUST, VERDICTS } from '../../content/site'
import './GuidePage.css'

const TOC = [
  ['quick-start', 'Quick start'], ['platforms', 'Platforms'], ['setup', 'Full setup'], ['concepts', 'How it fits'], ['components', 'What gets installed'], ['commands', 'Commands'], ['checks', 'Checks'],
  ['verdicts', 'Verdicts'], ['fix', 'If something is missing'], ['offline', 'Offline'], ['safety', 'How it stays safe'],
]

// [title, text, commands, note]. One list per platform; the Ubuntu one is the original walkthrough.
const WALK_LINUX = [
  ['Install Python 3.12 or newer', 'Check what you have. If it is older than 3.12, install a newer one with your package manager.',
    ['python3 --version', 'sudo apt install python3 python3-venv python3-pip'],
    'The apt line is for Debian and Ubuntu; other distributions have their own package names. The venv package is needed for the next steps.'],
  ['Install Docker Engine and start it', 'Docker downloads the images and runs every check in a locked-down container. Follow the official instructions for your distribution, then make sure the daemon runs and your user may use it.',
    ['docker --version', 'sudo systemctl enable --now docker', 'sudo usermod -aG docker $USER', 'docker info'],
    'Official instructions: https://docs.docker.com/engine/install/. After usermod, log out and back in. Members of the docker group have root-equivalent access to the machine, so add only users you trust. docker info must print without an error.'],
  ['Install SafeRun from the repository', 'SafeRun is installed from a checkout. It is not published on PyPI, and Semgrep and OSV-Scanner are not installed on your computer: they live in the analyzer image.',
    ['git clone https://github.com/vinay-repalle/saferun.git', 'cd saferun', 'python3 -m venv .venv', '.venv/bin/pip install -e .', 'source .venv/bin/activate', 'saferun --help'],
    'Activate the virtual environment (source .venv/bin/activate) in every new terminal.'],
  ['Install Cosign without sudo', 'Setup installs the signed analyzer image (analyzer-v1.0.1) and uses Cosign to check, before anything is pulled, that this project\'s release workflow signed it. Download the official binary into your own bin folder and put that folder on your PATH. Skip this only if you will build the analyzer yourself with --build-local.',
    ['mkdir -p ~/.local/bin', 'curl -fsSL -o cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64', 'install -m 0755 cosign ~/.local/bin/cosign', 'export PATH="$HOME/.local/bin:$PATH"', 'cosign version'],
    'Official page: https://docs.sigstore.dev/cosign/system_config/installation/. Compare sha256sum cosign with the checksums file on the cosign release page if you want to check the download. To keep the PATH change, add the export line to ~/.bashrc. On a machine with sudo you can install cosign with your package manager instead. SafeRun never downloads cosign for you.'],
  ['Set SafeRun up', 'Installs only what is missing, and verifies each part before trusting it. It pulls the Python and Node.js images by pinned digest, installs the signed analyzer image (it checks the Cosign signature, then pulls the exact pinned digest from ghcr.io, about 740 MB), and downloads the OSV vulnerability data (about 260 MB).',
    ['saferun init --all'],
    'Run saferun init without --all for a menu. To build the analyzer from the repository recipe instead (no Cosign needed, a few minutes, downloads from PyPI and GitHub), add --build-local for the analyzer: saferun init --only analyzer --build-local.'],
  ['Check that everything is ready', 'Every component should say ready. The exit code is 0 only when all of them are.',
    ['saferun status'], ''],
  ['Run your first scan', 'Scans a local folder. Nothing in it is executed, and the scan needs no network.',
    ['saferun scan ./my-project'],
    'Exit codes: 0 PASS, 1 FAIL, 2 WARNING (including any incomplete scan), 64 bad usage, 70 fatal error.'],
]

const WALK_WINDOWS = [
  ['Install Python 3.12 or newer', 'Download it from python.org if you do not have it. Tick "Add python.exe to PATH" in the installer, or use the py launcher.',
    ['py -3.12 --version'], 'Run the commands in PowerShell or Command Prompt.'],
  ['Install Docker Desktop and use Linux containers', 'Install Docker Desktop and start it. It must run Linux containers: right-click the Docker tray icon and choose "Switch to Linux containers" if you see that option.',
    ['docker version', 'docker info --format "{{.OSType}}"'],
    'The second command must print linux. Official instructions: https://docs.docker.com/desktop/setup/install/windows-install/. SafeRun itself does not need WSL. Docker Desktop integration on Windows has not yet been manually verified.'],
  ['Install SafeRun from the repository', 'SafeRun is installed from a checkout. It is not published on PyPI.',
    ['git clone https://github.com/vinay-repalle/saferun.git', 'cd saferun', 'py -3.12 -m venv .venv', '.venv\\Scripts\\pip install -e .', '.venv\\Scripts\\Activate.ps1', 'saferun --help'],
    'In Command Prompt activate with .venv\\Scripts\\activate.bat instead. If PowerShell blocks the script, use Command Prompt or call .venv\\Scripts\\saferun.exe directly.'],
  ['Cosign (optional)', 'The default setup checks the signed analyzer with Cosign 2.2 or newer (cosign.exe on your PATH). Install it from the official page. If you would rather not, build the analyzer locally in the next step.',
    ['cosign version'], 'Official page: https://docs.sigstore.dev/cosign/system_config/installation/. SafeRun never downloads cosign for you.'],
  ['Set SafeRun up', 'Pulls the pinned Python and Node.js images, installs the signed analyzer (about 740 MB) and downloads the OSV data (about 260 MB).',
    ['saferun init --all'], 'No Cosign? Use saferun init --only analyzer --build-local instead. The local build needs the checkout and internet.'],
  ['Check, then scan', 'Every component should say ready. Then scan a local folder; nothing in it is executed.',
    ['saferun status', 'saferun scan .\\my-project'], 'Keep the project on a local drive that Docker Desktop shares (C:\\Users by default). Network (UNC) paths are refused.'],
]

const WALK_MACOS = [
  ['Install Python 3.12 or newer', 'Check what you have. If it is older, install a newer one from python.org or with Homebrew.',
    ['python3 --version', 'brew install python@3.12'], 'The brew line is only needed if you use Homebrew and your Python is too old.'],
  ['Install Docker Desktop and start it', 'Install Docker Desktop (Apple Silicon or Intel) and open it once so the engine runs. It must use Linux containers, which is the macOS default.',
    ['docker version', 'docker info --format "{{.OSType}}"'],
    'The second command must print linux. Official instructions: https://docs.docker.com/desktop/setup/install/mac-install/. Docker Desktop integration on macOS has not yet been manually verified.'],
  ['Install SafeRun from the repository', 'SafeRun is installed from a checkout. It is not published on PyPI.',
    ['git clone https://github.com/vinay-repalle/saferun.git', 'cd saferun', 'python3 -m venv .venv', '.venv/bin/pip install -e .', 'source .venv/bin/activate', 'saferun --help'],
    'Activate the virtual environment in every new terminal.'],
  ['Cosign (optional)', 'The default setup checks the signed analyzer with Cosign 2.2 or newer on your PATH. If you would rather not, build the analyzer locally in the next step.',
    ['brew install cosign', 'cosign version'], 'Homebrew is one way; the official page lists others: https://docs.sigstore.dev/cosign/system_config/installation/. SafeRun never downloads cosign for you.'],
  ['Set SafeRun up', 'Pulls the pinned Python and Node.js images, installs the signed analyzer (about 740 MB) and downloads the OSV data (about 260 MB).',
    ['saferun init --all'], 'No Cosign? Use saferun init --only analyzer --build-local instead. The local build needs the checkout and internet.'],
  ['Check, then scan', 'Every component should say ready. Then scan a local folder; nothing in it is executed.',
    ['saferun status', 'saferun scan ./my-project'], 'Docker Desktop shares /Users, /private and /var/folders by default. With Colima or Lima, set TMPDIR to a shared folder.'],
]

// [id, tab label, walkthrough, intro line]
const OSES = [
  ['linux', 'Ubuntu / Linux', WALK_LINUX, 'Debian and Ubuntu commands. Other distributions use their own package names.'],
  ['windows', 'Windows', WALK_WINDOWS, 'Native Windows 10/11 with PowerShell or Command Prompt. WSL is not needed for SafeRun itself.'],
  ['macos', 'macOS', WALK_MACOS, 'Apple Silicon and Intel.'],
]

// [what, Ubuntu / Linux, Windows, macOS]
const DIFFS = [
  ['Docker', 'Docker Engine', 'Docker Desktop, Linux containers', 'Docker Desktop, Linux containers'],
  ['Analyzer image', 'linux/amd64, native', 'linux/amd64 (emulated on ARM)', 'linux/amd64 (emulated on Apple Silicon)'],
  ['Per-user data', '~/.local/share/saferun', '%LOCALAPPDATA%\\saferun', '~/Library/Application Support/saferun'],
  ['Special files', 'Symlinks are never followed', 'Symlinks, junctions and alternate data streams are skipped and reported', 'Symlinks are never followed'],
  ['Private files', 'Withheld unless world-readable', 'Withheld unless everyone who can read the project can read them', 'Withheld unless world-readable'],
  ['Verification', 'Full suite including Docker tests', 'Non-Docker tests in CI; Docker Desktop not yet manually verified', 'Non-Docker tests in CI; Docker Desktop not yet manually verified'],
]

const ARCH = [
  ['One shared core', 'The sandbox policy, the preflight, the signature check and the verdict logic are the same on every platform.'],
  ['One place that knows the OS', 'Only the host layer (saferun/hostos/) branches on the platform: file copying, locks, permissions and process cleanup.'],
  ['Linux containers everywhere', 'Untrusted code never runs on your computer. On Windows and macOS the checks run in Linux containers through Docker Desktop.'],
  ['Fails closed', 'Where a safe copy or a security check cannot be done on a platform, SafeRun withholds the file or refuses to run and says so in the report.'],
]

// Not part of the walkthrough: an optional check you can repeat at any time.
const FUTURE = [
  ['Verify the analyzer signature yourself', 'Repeats the signature check of the recorded analyzer release (analyzer-v1.0.1) on demand, online and with cosign. The pinned Python and Node.js images are checked as well.',
    ['saferun verify-images --signature'],
    'Expect VERIFIED on the cosign line and "all pinned images verified" at the end. Anything else prints NOT VERIFIED: do not rely on the images.'],
]

const CONCEPTS = [
  ['Docker downloads and runs the images', 'Setup uses it to pull images. Every scan then runs inside containers without network access, with your project mounted read-only.'],
  ['Cosign verifies the signed analyzer', 'Cosign checks the analyzer\'s signature against this project\'s release workflow and a release tag before the image is pulled, and the image must match the digest recorded in SafeRun. There is no unsigned download. A signature does not prove the project itself was never compromised. Whichever way it is installed, the analyzer is then locked locally.'],
  ['Python and Node.js images are pinned by digest', 'They are trusted only if Docker reports exactly the digest in SafeRun\'s source. A tag that merely exists is not enough. They are not cosign-checked; the digest is their anchor.'],
  ['Normal scans run without network', 'Setup is the only step that needs the internet (plus saferun osv-db update later). After it, scans work offline against the local OSV data.'],
]

const COMPONENTS = [
  { key: 'python', n: 1, title: 'Python sandbox image', does: 'Runs the Python syntax check in a locked-down container.', size: '~190 MB', enables: ['Python syntax'] },
  { key: 'node', n: 2, title: 'Node.js sandbox image', does: 'Runs the JavaScript syntax check in a locked-down container.', size: '~330 MB', enables: ['JavaScript syntax'] },
  { key: 'analyzer', n: 3, title: 'Analyzer image', does: 'Holds Semgrep, its rules and OSV-Scanner. Runs the static code analysis.', size: '~740 MB, signed download', enables: ['Static analysis', 'Dependency scan'] },
  { key: 'osv-db', n: 4, title: 'OSV vulnerability database', does: 'Local vulnerability data, so dependency scans run offline.', size: '~260 MB download', enables: ['Dependency scan'] },
]

const STATES = [
  ['READY', 'ready', 'Installed and verified just now.', 'Nothing to do.'],
  ['MISSING', 'warn', 'Not installed.', 'saferun init --only <name>'],
  ['INVALID', 'fail', 'Present but failed verification (wrong digest, changed lock, damaged data).', 'saferun init --only <name>  (analyzer: add --repair)'],
  ['OUTDATED', 'warn', 'Valid but older than 30 days (OSV data).', 'saferun osv-db update'],
]

const COMMANDS = [
  ['Guided setup: pick components from a menu', 'saferun init', 'Shows what is installed and verified, asks what to install. Press Enter for everything.'],
  ['Everything, no questions (scripts, CI)', 'saferun init --all', 'Add --yes to confirm prompts automatically.'],
  ['Only some components', 'saferun init --only python,node', 'Names: python, node, analyzer, osv-db.'],
  ['Everything except some', 'saferun init --skip osv-db', 'Use this if you do not need dependency scanning.'],
  ['Rebuild a failed analyzer', 'saferun init --only analyzer --repair', 'Replaces the analyzer image and its lock with a fresh install (the signature-checked release, or a local build with --build-local). Only when status says INVALID.'],
  ['Build the analyzer locally', 'saferun init --only analyzer --build-local', 'Builds it from the repository recipe instead of installing the signed download. Needs a SafeRun checkout and internet for PyPI and GitHub, not cosign. Never done automatically.'],
  ['Check the analyzer signature', 'saferun verify-images --signature', 'Online, needs cosign: confirms the recorded release is signed by this project\'s release workflow and names the pinned digest. Exit code 1 on any failure.'],
  ['Plain output for logs and CI', 'saferun scan ./my-project --color never', 'Colours, icons and the spinner appear only on a terminal; --format json is always plain. NO_COLOR is honoured.'],
  ['See what is installed', 'saferun status', 'Exit code 0 only when everything is ready. Add --format json for scripts.'],
  ['Update the vulnerability data', 'saferun osv-db update', 'The only command that uses the network. Sends nothing about your project.'],
  ['Check the data age and integrity', 'saferun osv-db status', 'Older than 30 days makes the dependency check incomplete.'],
]

const CHECKS = [
  ['Python syntax', 'python'], ['JavaScript syntax', 'node'], ['Static analysis (Semgrep)', 'analyzer'], ['Dependency vulnerabilities', 'analyzer + osv-db'],
]

const FIXES = [
  ['Setup says Docker is unusable, or docker: command not found (Linux)', 'Install Docker Engine and start it (sudo systemctl enable --now docker). docker info must work for your user. SafeRun only uses a local daemon and refuses remote ones.'],
  ['Docker says permission denied (Linux)', 'Your user is not in the docker group, or the group change is not active yet. Run sudo usermod -aG docker $USER, then log out and back in.'],
  ['Windows or macOS: SafeRun says it needs Linux containers, or Docker is unusable', 'Start Docker Desktop and make sure it runs Linux containers (on Windows: tray icon, Switch to Linux containers). docker info --format "{{.OSType}}" must print linux. Docker Desktop integration has not yet been manually verified, so please report what you see.'],
  ['Windows or macOS: the project folder is refused or cannot be mounted', 'Keep the project on a local drive that Docker Desktop shares. Windows: network (UNC) and \\?\\ paths are refused. macOS: /Users is shared by default; with Colima or Lima set TMPDIR to a shared folder.'],
  ['cosign: command not found, although you installed it', 'Its folder is not on your PATH in this terminal. Run export PATH="$HOME/.local/bin:$PATH", check with cosign version, and add the line to ~/.bashrc to keep it.'],
  ['saferun status shows an image as INVALID', 'Docker does not report the pinned digest for it (for example a tag that moved or an image loaded without its digest). Run saferun init --only python,node to pull the pinned one. Do not ignore an INVALID analyzer: see the --repair entry above.'],
  ['A check says "unavailable", "error" or "incomplete"', 'Run saferun status. It names the component and prints the exact fix, for example saferun init --only osv-db. A scan also prints that fix on stderr.'],
  ['A component says INVALID', 'Images are repaired by pulling the pinned digest. The analyzer is reinstalled only with --repair, because that replaces the image and its lock. Investigate first if you did not expect it.'],
  ['Setup says cosign is not installed', 'SafeRun checks the analyzer\'s signature before pulling anything and nothing was pulled. Install cosign 2.2 or newer (see the walkthrough) and run saferun init --only analyzer again, or build it yourself with saferun init --only analyzer --build-local.'],
  ['Setup says the signature could not be verified', 'Nothing was pulled or trusted. Check your internet access to ghcr.io and sigstore.dev, then retry. If it keeps failing, do not use --build-local to get around it without finding out why.'],
  ['The dependency scan says incomplete', 'The OSV data is older than 30 days. Run saferun osv-db update. Until then findings are still shown, but the result can never be PASS.'],
  ['Setup says there is no internet access, or you are offline', 'Setup needs Docker Hub, ghcr.io and sigstore.dev (signed analyzer; a local build needs PyPI and GitHub instead) and the OSV download once. Without them it keeps what is already valid and lists what is missing. See Working offline below; the analyzer cannot be installed on a machine that never has internet.'],
  ['Nothing is skipped silently', 'A check whose component is missing is reported, never skipped, and SafeRun never falls back to tools installed on your computer.'],
]

const OFFLINE = [
  'After setup, scans never need the internet: the checks run in containers without network and read the local OSV data.',
  'Without internet, saferun init uses what is already valid, skips downloads it does not need and lists what is missing.',
  'It never reports dependency scanning ready without valid OSV data.',
]
const PRELOAD = [
  ['OSV data', 'On a connected machine: saferun osv-db update --dir DIR. Copy DIR over and set SAFERUN_OSV_DB=DIR (or place it at the default location). Check with saferun osv-db status.'],
  ['Sandbox images', 'docker pull on a connected machine, then docker save / docker load. SafeRun trusts a loaded image only if Docker still reports the pinned digest; otherwise status says INVALID.'],
  ['Analyzer image', 'Cannot be installed without internet yet: the signed download needs ghcr.io, sigstore.dev and cosign (a local build needs PyPI and GitHub). Run saferun init --only analyzer once while online.'],
]

function tabKey(e, os, setOs) {
  const i = OSES.findIndex(([id]) => id === os)
  const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0
  if (!step) return
  e.preventDefault()
  const next = OSES[(i + step + OSES.length) % OSES.length][0]
  setOs(next)
  document.getElementById('tab-' + next)?.focus()
}

function jump(id) {
  const el = document.getElementById(id)
  if (!el) return
  const calm = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (el.scrollIntoView) el.scrollIntoView({ behavior: calm ? 'auto' : 'smooth', block: 'start' })
}

export function GuidePage() {
  const [active, setActive] = useState('quick-start')
  const [os, setOs] = useState('linux')
  const [, , walk, osIntro] = OSES.find(([id]) => id === os)
  // Highlight the section being read. Skipped where IntersectionObserver is missing (the sidebar still works by click).
  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined') return undefined
    const seen = new Map()
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) seen.set(e.target.id, e.isIntersecting)
      const first = TOC.find(([id]) => seen.get(id))
      if (first) setActive(first[0])
    }, { rootMargin: '-80px 0px -60% 0px' })
    for (const [id] of TOC) { const el = document.getElementById(id); if (el) io.observe(el) }
    return () => io.disconnect()
  }, [])
  return (
    <div className="shell">
      <SiteNav current="#/guide" />
      <main>
        <section className="g-hero">
          <div className="wrap g-hero-in">
          <Mark size={48} className="g-shield" />
          <div>
            <h1>Set up SafeRun in three steps</h1>
            <p className="g-lead">SafeRun checks code before you run or trust it, without ever running it. Setup installs only what each check needs, and verifies it.</p>
            <ul className="g-chips" aria-label="What SafeRun guarantees">
              {TRUST.map(([t]) => <li key={t}><span aria-hidden="true">✓</span> {t}</li>)}
            </ul>
          </div>
          </div>
        </section>

        <div className="wrap docs">
        <nav className="g-toc" aria-label="On this page">
          {TOC.map(([id, label]) => <button key={id} type="button" className={active === id ? 'on' : undefined} aria-current={active === id ? 'true' : undefined} onClick={() => { setActive(id); jump(id) }}>{label}</button>)}
        </nav>

        <div className="guide docs-body">
        <section id="quick-start" className="card g-section">
          <h2>Quick start</h2>
          <ol className="g-steps">
            {STEPS.map(([title, text, cmd], i) => (
              <li key={title}>
                <span className="g-num" aria-hidden="true">{i + 1}</span>
                <div><h3>{title}</h3><p>{text}</p><CommandBlock command={cmd} /></div>
              </li>
            ))}
          </ol>
          <p className="fine">Needs Python 3.12+, a local Docker that runs Linux containers and internet access for setup (the signed analyzer is checked with cosign 2.2+). Pick your platform under Full setup below.</p>
        </section>

        <section id="platforms" className="card g-section">
          <h2>Platforms</h2>
          <p>SafeRun runs on Ubuntu/Linux, native Windows and macOS. Every platform needs a local Docker that runs Linux containers; installing SafeRun does not install Docker.</p>
          <div className="g-grid">
            {PLATFORMS.map(([name, status, note]) => (
              <article key={name} className="g-comp g-plat"><h3>{name}</h3><p className="g-enables"><span className="g-pill">{status}</span></p><p>{note}</p></article>
            ))}
          </div>
          <p className="notice">Docker Desktop integration on Windows and macOS has not yet been manually verified. CI cannot run Linux containers on those systems, so the sandbox and analyzer tests there were not run.</p>
          <h3>How it works across platforms</h3>
          <dl className="g-defs">{ARCH.map(([a, b]) => <div key={a}><dt>{a}</dt><dd>{b}</dd></div>)}</dl>
          <h3>Differences and limitations</h3>
          <div className="g-scroll">
            <table>
              <thead><tr><th></th>{OSES.map(([id, label]) => <th key={id}>{label}</th>)}</tr></thead>
              <tbody>{DIFFS.map(([what, ...cells]) => <tr key={what}><th scope="row">{what}</th>{cells.map((c, i) => <td key={i}>{c}</td>)}</tr>)}</tbody>
            </table>
          </div>
          <p className="fine">Windows: the project and the temp folder must be on a local drive shared with Docker Desktop; Windows containers mode is refused. Details: <a href={DOCS + 'platforms.md'} target="_blank" rel="noreferrer noopener">platform status</a>.</p>
        </section>

        <section id="setup" className="card g-section">
          <h2>Full setup, step by step</h2>
          <p>New to this? Choose your platform, then follow the steps in order. Each command can be copied with its button.</p>
          <div className="g-tabs" role="tablist" aria-label="Platform">
            {OSES.map(([id, label]) => (
              <button key={id} type="button" role="tab" id={'tab-' + id} aria-selected={os === id} aria-controls="os-panel" tabIndex={os === id ? 0 : -1}
                className={os === id ? 'on' : undefined} onClick={() => setOs(id)} onKeyDown={(e) => tabKey(e, os, setOs)}>{label}</button>
            ))}
          </div>
          <div id="os-panel" role="tabpanel" aria-labelledby={'tab-' + os}>
          <p className="fine">{osIntro}</p>
          <h3>What you need</h3>
          <dl className="g-defs">{REQUIREMENTS.map(([a, b]) => <div key={a}><dt>{a}</dt><dd>{b}</dd></div>)}</dl>
          <ol className="g-walk">
            {walk.map(([title, text, cmds, note], i) => (
              <li key={title}>
                <span className="g-num" aria-hidden="true">{i + 1}</span>
                <div>
                  <h3>{title}</h3>
                  <p>{text}</p>
                  {cmds.map((c) => <CommandBlock key={c} command={c} />)}
                  {note && <p className="fine">{note}</p>}
                </div>
              </li>
            ))}
          </ol>
          </div>
          <div className="g-future">
            <h3>Verify the signed analyzer release</h3>
            <p className="fine">Optional: repeat the signature check whenever you like. It needs internet and cosign.</p>
            <ul>
              {FUTURE.map(([title, text, cmds, note]) => (
                <li key={title}>
                  <h4>{title}</h4>
                  <p>{text}</p>
                  {cmds.map((c) => <CommandBlock key={c} command={c} />)}
                  {note && <p className="fine">{note}</p>}
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section id="concepts" className="card g-section">
          <h2>How the pieces fit together</h2>
          <dl className="g-defs">{CONCEPTS.map(([a, b]) => <div key={a}><dt>{a}</dt><dd>{b}</dd></div>)}</dl>
        </section>

        <section id="components" className="card g-section">
          <h2>What gets installed, and why</h2>
          <div className="g-grid">
            {COMPONENTS.map((c) => (
              <article key={c.key} className="g-comp">
                <header><span className="g-num small" aria-hidden="true">{c.n}</span><code className="g-key">{c.key}</code></header>
                <h3>{c.title}</h3>
                <p>{c.does}</p>
                <p className="fine">{c.size}</p>
                <p className="g-enables">{c.enables.map((e) => <span key={e} className="g-pill">{e}</span>)}</p>
              </article>
            ))}
          </div>
          <h3>What the status of each part means</h3>
          <div className="g-states">
            {STATES.map(([name, tone, meaning, fix]) => (
              <div key={name} className="g-state">
                <span className={`g-badge ${tone}`}>{name}</span>
                <span>{meaning}</span>
                <code>{fix}</code>
              </div>
            ))}
          </div>
        </section>

        <section id="commands" className="card g-section">
          <h2>Commands</h2>
          <ul className="g-cmds">
            {COMMANDS.map(([title, cmd, note]) => (
              <li key={cmd}><h3>{title}</h3><CommandBlock command={cmd} label={title} /><p className="fine">{note}</p></li>
            ))}
          </ul>
        </section>

        <section id="checks" className="card g-section">
          <h2>Which part powers which check</h2>
          <table>
            <thead><tr><th>Check</th><th>Needs</th></tr></thead>
            <tbody>{CHECKS.map(([a, b]) => <tr key={a}><td>{a}</td><td><code>{b}</code></td></tr>)}</tbody>
          </table>
          <p className="fine">Not installed on purpose: Semgrep and OSV-Scanner never run on your computer, only inside the analyzer container. Running your tests and installing dependencies are planned, not available.</p>
        </section>

        <section id="verdicts" className="card g-section">
          <h2>Reading the verdict</h2>
          <div className="g-verdicts">
            {VERDICTS.map(([tone, icon, name, meaning, action]) => (
              <article key={name} className={`g-verdict ${tone}`}>
                <span className="g-vicon" aria-hidden="true">{icon}</span>
                <h3>{name}</h3>
                <p>{meaning}</p>
                <p className="g-action">{action}</p>
              </article>
            ))}
          </div>
        </section>

        <section id="fix" className="card g-section">
          <h2>If something is missing or outdated</h2>
          <div className="g-faq">
            {FIXES.map(([q, a]) => <details key={q}><summary>{q}</summary><p>{a}</p></details>)}
          </div>
        </section>

        <section id="offline" className="card g-section">
          <h2>Working offline</h2>
          <ul className="g-list">{OFFLINE.map((t) => <li key={t}>{t}</li>)}</ul>
          <h3>Preparing a machine without internet</h3>
          <dl className="g-defs">{PRELOAD.map(([a, b]) => <div key={a}><dt>{a}</dt><dd>{b}</dd></div>)}</dl>
        </section>

        <section id="safety" className="card g-section">
          <h2>How SafeRun stays safe</h2>
          <ul className="g-safety">
            {SAFETY.map(([a, b]) => <li key={a}><span className="g-tick" aria-hidden="true">✓</span><div><strong>{a}</strong><p>{b}</p></div></li>)}
          </ul>
          <p className="notice">{HONEST_LIMITS}</p>
        </section>

        </div>
        </div>
      </main>
      <SiteFooter />
    </div>
  )
}
