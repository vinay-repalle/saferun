// @vitest-environment jsdom
import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { BenchmarksPage } from './BenchmarksPage'

describe('Benchmarks page', () => {
  it('shows the real held-out numbers and the honest limits', () => {
    const text = render(<BenchmarksPage />).container.textContent
    for (const k of ['9/32', '14/32', '17/32', '7/32', '0/12', '2/12', 'Not an independent evaluation', 'still behind Bandit']) expect(text).toContain(k)
  })
})
