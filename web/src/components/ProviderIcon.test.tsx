import { fireEvent, render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import ProviderIcon from './ProviderIcon'

describe('ProviderIcon', () => {
  it('loads only constrained local file references and falls back after a missing image', () => {
    const data = '/account/provider-icons/' + 'a'.repeat(64) + '.png'
    const { container, rerender } = render(<ProviderIcon icon="microsoft" data={data} />)
    expect(container.querySelector('img')).toHaveAttribute('src', data)
    fireEvent.error(container.querySelector('img')!)
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('svg')).not.toBeNull()
    rerender(<ProviderIcon icon="microsoft" data={'/account/provider-icons/' + 'b'.repeat(64) + '.png'} />)
    expect(container.querySelector('img')).not.toBeNull()
    rerender(<ProviderIcon icon="microsoft" data="/account/provider-icons/../secrets" />)
    expect(container.querySelector('img')).toBeNull()
  })
  it('uses an embedded custom PNG and keeps external URLs on the default icon', () => {
    const data = 'data:image/png;base64,aWNvbg=='
    const custom = render(<ProviderIcon icon="key" data={data} />).container
    expect(custom.querySelector('img')).toHaveAttribute('src', data)
    expect(custom.querySelector('img')).toHaveAttribute('alt', '')
    const remote = render(<ProviderIcon icon="key" data="https://icons.test/icon.svg" />).container
    expect(remote.querySelector('img')).toBeNull()
    expect(remote.querySelector('svg')).not.toBeNull()
  })
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
