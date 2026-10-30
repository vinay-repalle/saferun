import { txt } from '../../utils/report'

const fmt = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`)

export function ArchiveCard({ a }) {
  return (
    <section className="card" aria-label="Archive">
      <h2>Archive</h2>
      <dl className="kpis">
        <div><dt>Files extracted</dt><dd>{a.files}</dd></div>
        <div><dt>Directories</dt><dd>{a.dirs}</dd></div>
        <div><dt>Size</dt><dd>{fmt(a.bytes)}</dd></div>
      </dl>
      {a.stripped_prefix && <p className="small">Single top-level folder <code>{txt(a.stripped_prefix, 200)}</code> was removed; paths below are relative to it.</p>}
      {a.excluded_total > 0 && (
        <details open>
          <summary>{a.excluded_total} member(s) excluded (macOS metadata) and not scanned</summary>
          <ul className="small">{a.excluded.map((e, i) => <li key={i}><code>{txt(e, 300)}</code></li>)}{a.excluded_total > a.excluded.length && <li>… and {a.excluded_total - a.excluded.length} more</li>}</ul>
        </details>
      )}
    </section>
  )
}
