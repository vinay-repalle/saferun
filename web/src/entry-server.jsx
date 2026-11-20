import { StrictMode } from 'react'
import { renderToString } from 'react-dom/server'
import { App } from './App'
import { PATHS } from './router'
import { headHtml, llmsTxt, robotsTxt, sitemapXml } from './seo'

// Server entry, used only by scripts/prerender.js at build time: each page rendered to HTML, and the file it is written to.
export const FILES = [['home', 'index.html'], ['guide', 'guide.html'], ['benchmarks', 'benchmarks.html'], ['notfound', '404.html']]

export function render(page) {
  return { html: renderToString(<StrictMode><App url={PATHS[page] ?? '/404'} /></StrictMode>), head: headHtml(page) }
}

export { llmsTxt, robotsTxt, sitemapXml }
