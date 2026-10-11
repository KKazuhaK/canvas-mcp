import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import ProviderIcon from './ProviderIcon'

describe('ProviderIcon', () => {
  it.each(['microsoft', 'google', 'github', 'key', 'something-new'])(
    'draws %s as inline SVG with nothing remote in it',
    (icon) => {
      const { container } = render(<ProviderIcon icon={icon} />)
      const svg = container.querySelector('svg')
      expect(svg).not.toBeNull()
      expect(svg?.getAttribute('aria-hidden')).toBe('true')
      const markup = container.innerHTML
      expect(markup).not.toMatch(/https?:|\/\/|url\(|<image|<img|<use|xlink:href|href=/i)
      expect(svg?.querySelectorAll('path, rect').length).toBeGreaterThan(0)
    },
  )

  it('draws the Google G in four colours and the GitHub mark in the text colour', () => {
    const google = render(<ProviderIcon icon="google" />).container
    expect(new Set([...google.querySelectorAll('path')].map((p) => p.getAttribute('fill'))).size).toBe(4)
    const github = render(<ProviderIcon icon="github" />).container
    expect(github.querySelector('path')?.getAttribute('fill')).toBe('currentColor')
  })

  it('falls back to the key for an icon it does not know', () => {
    const known = render(<ProviderIcon icon="key" />).container.innerHTML
    const unknown = render(<ProviderIcon icon="nope" />).container.innerHTML
    expect(unknown).toBe(known)
  })
})
