import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { http } from './api/client'
import { initI18n } from './i18n'
import { makeQueryClient } from './query/client'
import { wireSession } from './query/session'
import { createAppRouter } from './router'

async function bootstrap() {
  // Dev-only mock API. `import.meta.env.DEV` is replaced by `false` in a
  // production build, so this whole branch (and the dynamic import inside it) is
  // removed; scripts/check-dist.mjs proves nothing from src/dev ships.
  if (import.meta.env.DEV && import.meta.env.VITE_MOCK === '1') {
    const { installMockServer } = await import('./dev/mockServer')
    installMockServer(http)
  }

  await initI18n()

  const client = makeQueryClient()
  const router = createAppRouter()
  wireSession(client, router)

  const root = document.getElementById('root')
  if (!root) throw new Error('missing #root')
  createRoot(root).render(
    <StrictMode>
      <App client={client} router={router} />
    </StrictMode>,
  )
}

void bootstrap()
