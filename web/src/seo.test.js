import { describe, expect, it } from 'vitest'
import { VERSION } from './content/site'
import { headHtml, headTags, llmsTxt, robotsTxt, SITE_URL, sitemapXml } from './seo'

const attr = (page, key, value, name = 'content') => headTags(page).find(([, a]) => a[key] === value)?.[1][name]

describe('Search and sharing metadata', () => {
  it('each page has its own description, canonical address and share card', () => {
    for (const [page, path] of [['home', '/'], ['guide', '/guide'], ['benchmarks', '/benchmarks']]) {
      expect(attr(page, 'rel', 'canonical', 'href')).toBe(SITE_URL + path)
      expect(attr(page, 'property', 'og:url')).toBe(SITE_URL + path)
      expect(attr(page, 'property', 'og:image')).toBe(SITE_URL + '/og.png')
      expect(attr(page, 'name', 'twitter:card')).toBe('summary_large_image')
      expect(attr(page, 'name', 'robots')).toBeUndefined()
    }
    expect(new Set(['home', 'guide', 'benchmarks'].map((p) => attr(p, 'name', 'description'))).size).toBe(3)
    expect(attr('home', 'name', 'description')).toContain(VERSION)
  })

  it('the not-found page is noindex and has no canonical address', () => {
    expect(attr('notfound', 'name', 'robots')).toBe('noindex')
    expect(attr('notfound', 'rel', 'canonical', 'href')).toBeUndefined()
  })

  it('the home page describes the software as structured data, with no ratings or reviews', () => {
    const ld = headTags('home').find(([t]) => t === 'script')
    const data = JSON.parse(ld[2])
    expect(data).toMatchObject({ '@type': 'SoftwareApplication', name: 'SafeRun', softwareVersion: VERSION, url: SITE_URL + '/' })
    expect(data).not.toHaveProperty('aggregateRating')
    expect(data).not.toHaveProperty('review')
    expect(headTags('guide').some(([t]) => t === 'script')).toBe(false)
  })

  it('writes safe HTML', () => {
    const html = headHtml('home')
    expect(html.startsWith('<title>SafeRun: check code before you run it</title>')).toBe(true)
    expect(html).not.toMatch(/<\/script>[\s\S]*<\/script>/) // one script element, never closed early
    for (const [, attrs] of headTags('home')) expect(attrs).toHaveProperty('data-head', '')
  })

  it('robots.txt allows every crawler and names the sitemap; the sitemap lists the three pages', () => {
    expect(robotsTxt()).toMatch(/User-agent: \*\nAllow: \//)
    expect(robotsTxt()).not.toMatch(/Disallow/)
    expect(robotsTxt()).toContain(`Sitemap: ${SITE_URL}/sitemap.xml`)
    const locs = [...sitemapXml().matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1])
    expect(locs).toEqual([SITE_URL + '/', SITE_URL + '/guide', SITE_URL + '/benchmarks'])
  })

  it('llms.txt is an honest summary with the version, limits and links', () => {
    const t = llmsTxt()
    expect(t.startsWith('# SafeRun\n\n> ')).toBe(true)
    for (const k of [VERSION, 'pip install saferun-cli', 'Python only', 'not been independently certified', 'not that the code is safe', 'partly verified', SITE_URL + '/guide', 'benchmark.md']) expect(t).toContain(k)
  })
})
