import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect } from 'vitest'

/** Follow the actual list -> selected account -> task workflow. */
export async function openManagedAccount(name: string, topic?: string): Promise<HTMLElement> {
  const user = userEvent.setup()
  let drawer = screen.queryByRole('dialog', { name })
  if (!drawer) {
    await waitFor(() => {
      const dialog = screen.queryByRole('dialog')
      if (dialog) expect(within(dialog).queryByRole('button', { name: 'Close' })).not.toBeNull()
    })
    const previous = screen.queryByRole('dialog')
    if (previous) {
      await user.click(within(previous).getByRole('button', { name: 'Close' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    }
    await user.click(await screen.findByRole('button', { name: `Manage ${name}` }))
    drawer = await screen.findByRole('dialog', { name })
  }
  if (topic) await user.click(within(drawer).getByRole('tab', { name: topic }))
  return drawer
}
