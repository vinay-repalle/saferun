import { ALPHA_NOTICE, DOCS, GITHUB, INSTALL, PYPI, RELEASES, SECURITY_POLICY, VERSION } from './content/site'
import { PATHS } from './router'

// Search and sharing metadata. The page <head> (pre-rendered by scripts/prerender.js, kept in step by applyHead on the client), robots.txt,
// sitemap.xml and llms.txt are all built from here. When the site moves to its own domain, change SITE_URL only.
export const SITE_URL = 'https://safe-run.netlify.app'
const IMAGE = SITE_URL + '/og.png' // 1200 x 630, made from scripts/og-image.html
const url = (page) => SITE_URL + PATHS[page]

export const META = {
  home: {
    title: 'SafeRun: check code before you run it',
    description: `SafeRun ${VERSION} (alpha) is on PyPI: ${INSTALL}. Static validation, dependency scanning and sandboxed execution of untrusted Python code, on Linux, Windows and macOS with Docker.`,
  },
  guide: {
    title: 'Setup guide · SafeRun',
    description: `Install and set up SafeRun ${VERSION} on Ubuntu/Linux, Windows or macOS: requirements, the three setup steps, every command, check and verdict, offline use and troubleshooting.`,
  },
  benchmarks: {
    title: 'Benchmark: SafeRun vs Bandit · SafeRun',
    description: 'A small, advisory comparison of SafeRun and Bandit on harmless simulated Python samples: held-out results, numbers per category and the limits. Not an independent evaluation.',
  },
  notfound: { title: 'Page not found · SafeRun', description: 'This page does not exist. SafeRun checks code before you run it.', noindex: true },
}

// Structured data for search engines: what the software is, nothing more (no ratings or reviews).
const SOFTWARE = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'SafeRun',
  alternateName: 'saferun-cli',
  description: 'A command-line tool that checks untrusted Python code before you run it: static analysis, hardcoded-secrets and dependency vulnerability scans in an offline container, and a PASS, WARNING or FAIL verdict.',
  url: url('home'),
  applicationCategory: 'DeveloperApplication',
  applicationSubCategory: 'Security',
  operatingSystem: 'Linux, Windows, macOS',
  softwareVersion: VERSION,
  softwareRequirements: 'Python 3.12+, Docker',
  downloadUrl: PYPI,
  license: 'https://opensource.org/licenses/MIT',
  isAccessibleForFree: true,
  offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
  sameAs: [GITHUB, PYPI],
}

/** The <head> tags of a page, as [tag, attributes, text?]. Every one carries data-head, so the client can swap them all on navigation. */
export function headTags(page) {
  const m = META[page]
  const tags = [['meta', { name: 'description', content: m.description }]]
  if (m.noindex) tags.push(['meta', { name: 'robots', content: 'noindex' }])
  else tags.push(['link', { rel: 'canonical', href: url(page) }])
  tags.push(
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'SafeRun' }],
    ['meta', { property: 'og:title', content: m.title }],
    ['meta', { property: 'og:description', content: m.description }],
    ['meta', { property: 'og:url', content: m.noindex ? url('home') : url(page) }],
    ['meta', { property: 'og:image', content: IMAGE }],
    ['meta', { property: 'og:image:width', content: '1200' }],
    ['meta', { property: 'og:image:height', content: '630' }],
    ['meta', { property: 'og:image:alt', content: 'SafeRun: check the code before you run it.' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: m.title }],
    ['meta', { name: 'twitter:description', content: m.description }],
    ['meta', { name: 'twitter:image', content: IMAGE }],
  )
  // "<" is escaped so the JSON can never close the script element early.
  if (page === 'home') tags.push(['script', { type: 'application/ld+json' }, JSON.stringify(SOFTWARE).replace(/</g, '\\u003c')])
  return tags.map(([tag, attrs, text]) => [tag, { ...attrs, 'data-head': '' }, text])
}

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

/** The page's <title> and head tags as HTML, for the pre-rendered files. */
export function headHtml(page) {
  const tags = headTags(page).map(([tag, attrs, text]) => {
    const a = Object.entries(attrs).map(([k, v]) => (v === '' ? ` ${k}` : ` ${k}="${esc(v)}"`)).join('')
    return text === undefined ? `<${tag}${a} />` : `<${tag}${a}>${text}</${tag}>`
  })
  return [`<title>${esc(META[page].title)}</title>`, ...tags].join('\n    ')
}

/** Updates the title and head tags in the browser after an in-page navigation. */
export function applyHead(page) {
  document.title = META[page].title
  document.head.querySelectorAll('[data-head], meta[name=description]').forEach((el) => el.remove())
  for (const [tag, attrs, text] of headTags(page)) {
    const el = document.createElement(tag)
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v)
    if (text !== undefined) el.textContent = text
    document.head.append(el)
  }
}

export const robotsTxt = () => `# Every crawler, search engines and AI tools included, may read the whole site.
User-agent: *
Allow: /

Sitemap: ${SITE_URL}/sitemap.xml
`

export const sitemapXml = () => `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${Object.keys(PATHS).map((p) => `  <url><loc>${url(p)}</loc></url>`).join('\n')}
</urlset>
`

/** A plain-text summary for AI tools (https://llmstxt.org): what SafeRun is, honestly, and where to read more. */
export const llmsTxt = () => `# SafeRun

> SafeRun is a command-line tool that checks untrusted Python code (AI-generated or downloaded projects) before you run or trust it. Scanning never executes the code: static analysis (Semgrep with bundled Python rules), a hardcoded-secrets scan (gitleaks) and a dependency vulnerability scan (OSV-Scanner against local data) run inside a locked-down, offline Docker container, and the result is a PASS, WARNING or FAIL verdict.

- Current release: ${VERSION} (alpha) on PyPI. Install: \`${INSTALL}\`, then \`saferun init\` and \`saferun doctor\`.
- Needs Python 3.12+ and a local Docker. Ubuntu/Linux is fully tested; native Windows 10/11 and macOS are partly verified (Docker Desktop integration not yet manually verified).
- Python only: JavaScript and npm files are not checked.
- \`saferun scan\` only reads files. \`saferun run\` scans a Python script and runs it, inside the sandbox only, if the verdict allows.
- ${ALPHA_NOTICE}
- MIT license.

## Website

- [Home](${url('home')}): what SafeRun checks, how it works, its security model, a sample report, quick start and FAQ
- [Setup guide](${url('guide')}): requirements and setup for Ubuntu/Linux, Windows and macOS, every command, check and verdict, offline use, troubleshooting
- [Benchmark](${url('benchmarks')}): advisory comparison with Bandit on simulated samples, with its limits

## Docs

- [CLI reference](${DOCS}cli.md): commands, options, output and exit codes
- [Engine](${DOCS}engine.md): how the checks and verdicts work
- [Benchmark report](${DOCS}benchmark.md): method, results and every miss
- [Release images](${DOCS}release-images.md): the signed, digest-pinned analyzer image
- [Security policy](${SECURITY_POLICY})

## Links

- [Source code on GitHub](${GITHUB})
- [PyPI package](${PYPI})
- [Releases](${RELEASES})
`
