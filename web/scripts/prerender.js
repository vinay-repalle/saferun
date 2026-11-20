// Runs after `vite build` (npm run build). Renders every page to static HTML, so search engines and AI tools that do not run JavaScript
// still read the real text, then writes robots.txt, sitemap.xml and llms.txt. The browser takes over each page where it stands (hydration).
import { readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { build } from 'vite'

const root = fileURLToPath(new URL('..', import.meta.url))
const dist = join(root, 'dist')
const tmp = join(root, 'node_modules', '.saferun-prerender') // inside node_modules so the bundle finds react there

try {
  await build({ root, logLevel: 'warn', build: { ssr: 'src/entry-server.jsx', outDir: tmp, emptyOutDir: true, copyPublicDir: false } })
  const entry = (await readdir(tmp)).find((f) => /^entry-server\.m?js$/.test(f))
  const ssr = await import(pathToFileURL(join(tmp, entry)).href)

  const template = await readFile(join(dist, 'index.html'), 'utf8')
  const cut = (s, re) => { if (!re.test(s)) throw new Error('index.html changed: ' + re); return s.replace(re, '') }
  const base = cut(cut(template, /\s*<!--[^>]*dev server only[^>]*-->/), /\s*<title>[^<]*<\/title>\s*<meta name="description"[^>]*>/)
  if (!base.includes('<div id="root"></div>')) throw new Error('index.html changed: no empty #root')

  for (const [page, file] of ssr.FILES) {
    const { html, head } = ssr.render(page)
    const out = base.replace(/\s*<\/head>/, () => `\n    ${head}\n  </head>`).replace('<div id="root"></div>', () => `<div id="root" data-page="${page}">${html}</div>`)
    await writeFile(join(dist, file), out)
  }
  await writeFile(join(dist, 'robots.txt'), ssr.robotsTxt())
  await writeFile(join(dist, 'sitemap.xml'), ssr.sitemapXml())
  await writeFile(join(dist, 'llms.txt'), ssr.llmsTxt())
  console.log('pre-rendered: ' + ssr.FILES.map(([, f]) => f).join(', ') + ' + robots.txt, sitemap.xml, llms.txt')
} finally {
  await rm(tmp, { recursive: true, force: true })
}
