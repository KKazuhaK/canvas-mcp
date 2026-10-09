import { screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { hardNavigate } from '@/utils/navigate'
import { renderApp } from '@/test/renderWithProviders'
import { errorBody, scriptAdapter } from '@/test/fixtures'

vi.mock('@/utils/navigate', () => ({ hardNavigate: vi.fn() }))

describe('LoginView', () => {
  beforeEach(() => {
    vi.mocked(hardNavigate).mockClear()
  })

  it('renders one sign-in link per provider', async () => {
    await renderApp('/login', 'signed-out')
    const microsoft = await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    const google = screen.getByRole('link', { name: /Sign in with Google/ })
    const github = screen.getByRole('link', { name: /Sign in with GitHub/ })
    expect(microsoft).toHaveAttribute('href', '/account/api/login/entra/start')
    expect(google).toHaveAttribute('href', '/account/api/login/google/start')
    expect(github).toHaveAttribute('href', '/account/api/login/github/start')
    expect(screen.getAllByRole('link', { name: /Sign in with/ })).toHaveLength(3)
    expect(screen.getByRole('heading', { name: 'Canvas account' })).toBeInTheDocument()
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('passes a valid txn and return_to through to the start URL', async () => {
    await renderApp('/login?txn=t_9f2&return_to=%2Faccount%2Fconsent%2Ft_9f2', 'signed-out')
    const link = await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(link).toHaveAttribute(
      'href',
      '/account/api/login/entra/start?txn=t_9f2&return_to=%2Faccount%2Fconsent%2Ft_9f2',
    )
  })

  it.each([
    ['//evil.example'],
    ['https://evil.example/account'],
    ['/\\evil.example'],
    ['javascript:alert(1)'],
  ])('drops an unsafe return_to (%s)', async (bad) => {
    await renderApp(`/login?return_to=${encodeURIComponent(bad)}&txn=has%20space`, 'signed-out')
    const link = await screen.findByRole('link', { name: /Sign in with Microsoft/ })
    expect(link).toHaveAttribute('href', '/account/api/login/entra/start')
  })

  it('redirects automatically only when there is exactly one provider and no error', async () => {
    await renderApp('/login?txn=t_9f2', 'single-provider')
    await waitFor(() => expect(hardNavigate).toHaveBeenCalledTimes(1))
    expect(hardNavigate).toHaveBeenCalledWith('/account/api/login/entra/start?txn=t_9f2')
    expect(await screen.findByText(/Taking you to Microsoft/)).toBeInTheDocument()
  })

  it('does not redirect (loop guard) when the single provider just failed', async () => {
    await renderApp('/login?error=provider_error', 'single-provider')
    expect(await screen.findByRole('link', { name: /Sign in with Microsoft/ })).toBeInTheDocument()
    expect(hardNavigate).not.toHaveBeenCalled()
    expect(screen.getByRole('alert')).toHaveTextContent('Sign-in did not complete')
    expect(screen.getByRole('alert')).toHaveTextContent('could not complete the request')
  })

  it('does not redirect with several providers', async () => {
    await renderApp('/login', 'signed-out')
    await screen.findAllByRole('link', { name: /Sign in with/ })
    expect(hardNavigate).not.toHaveBeenCalled()
  })

  it('shows a localized message for a closed-set error and never the raw value', async () => {
    await renderApp('/login?error=not_provisioned', 'signed-out')
    expect(await screen.findByRole('alert')).toHaveTextContent('invite-only')
  })

  it('treats an unknown error value as the generic message without echoing it', async () => {
    await renderApp('/login?error=%3Cb%3Eowned%3C%2Fb%3E', 'signed-out')
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Something went wrong on our side')
    expect(alert).not.toHaveTextContent('owned')
    expect(document.body.innerHTML).not.toContain('<b>owned')
  })

  it('explains an empty provider list', async () => {
    await renderApp('/login', 'no-provider')
    expect(await screen.findByText('No sign-in method is set up')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Sign in with/ })).toBeNull()
  })

  it('offers a retry when the providers cannot be loaded', async () => {
    await renderApp('/login', 'signed-out', () => {
      scriptAdapter(() => ({ status: 500, data: errorBody('internal_error') }))
    })
    expect(await screen.findByText('Could not load the sign-in options')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Sign in with/ })).toBeNull()
  })
})
