import { SiteFooter } from '../../components/SiteFooter/SiteFooter'
import { SiteNav } from '../../components/SiteNav/SiteNav'
import { BENCH_CATEGORIES, BENCH_LIMITS, BENCH_ROWS } from '../../content/benchmark'
import { DOCS } from '../../content/site'
import './BenchmarksPage.css'

/** The benchmark results, from docs/benchmark.md. Every bar also prints its k/n, so colour is never the only signal. */
export function BenchmarksPage() {
  return (
    <div className="shell">
      <SiteNav current="#/benchmarks" />
      <main className="wrap bench">
        <h1>Benchmark: SafeRun vs Bandit</h1>
        <p className="g-lead">A small, advisory comparison on harmless simulated samples that are never executed. Held-out split of the second sample set: 32 bad and 12 clean code samples.</p>
        <p className="notice">Not an independent evaluation. SafeRun is behind Bandit on catches; the new rules help it, but do not close the gap.</p>

        {BENCH_ROWS.map(([title, n, note, series]) => (
          <section key={title} className="card bench-row" aria-label={title}>
            <h2>{title}</h2>
            <p className="fine">{note}</p>
            {series.map(([name, k, key]) => (
              <div key={name} className="bench-bar">
                <span className="bench-name">{name}</span>
                <span className="bench-track" aria-hidden="true"><i className={'b-' + key} style={{ width: (100 * k / n) + '%' }} /></span>
                <span className="bench-val">{k}/{n}</span>
              </div>
            ))}
          </section>
        ))}

        <section className="card">
          <h2>By category (loose, flagged / total)</h2>
          <div className="g-scroll">
            <table>
              <thead><tr><th>Category</th><th>SafeRun, unchanged</th><th>SafeRun, new rules</th><th>Bandit</th></tr></thead>
              <tbody>{BENCH_CATEGORIES.map(([c, ...v]) => <tr key={c}><th scope="row">{c}</th>{v.map((x, i) => <td key={i}>{x}</td>)}</tr>)}</tbody>
            </table>
          </div>
          <p className="fine">The three new rules cover credential-file reads, persistence setup and hidden function lookups. Five held-out samples were gained and none was lost. Dependency checks: SafeRun and pip-audit tie at 8/8 on the first set.</p>
        </section>

        <section className="card">
          <h2>Limits</h2>
          <ul className="g-list">{BENCH_LIMITS.map((t) => <li key={t}>{t}</li>)}</ul>
          <p className="fine">Full report, method and every miss: <a href={DOCS + 'benchmark.md'} target="_blank" rel="noreferrer noopener">docs/benchmark.md</a>.</p>
        </section>
      </main>
      <SiteFooter />
    </div>
  )
}
