import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// `npm run dev:mock` only: the sign-in is a full-page navigation to the server's
// /account/login redirect, which has no mock behind it. This stub just bounces back
// into the app (honouring a valid return_to, else the account page).
function mockLoginBounce(): Plugin {
  return {
    name: 'mock-login-bounce',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url && /^\/account\/login(?:[/?#]|$)/.test(req.url)) {
          const raw = new URL(req.url, 'http://localhost').searchParams.get('return_to')
          const back = raw && !raw.includes('..') && /^\/account(?:\/[A-Za-z0-9._~%/-]*)?$/.test(raw) ? raw : '/account/'
          res.statusCode = 302
          res.setHeader('Location', `${back}${back.includes('?') ? '&' : '?'}mock=enrolled`)
          res.end()
          return
        }
        next()
      })
    },
  }
}

// The Python server (ACCOUNT_UI=react) mounts the built app at /account/ (assets
// under /account/assets/) and answers every other GET below /account/ that is not
// /account/api/* with index.html. Because the mount path is fixed, assets use
// absolute URLs and no <base href> trick is needed for deep links.
export default defineConfig(({ mode }) => ({
  base: '/account/',
  plugins: [react(), ...(mode === 'mock' ? [mockLoginBounce()] : [])],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, 'src'),
    },
  },
  server: {
    port: 5175,
    host: '127.0.0.1',
    proxy: {
      // Session cookies are passed through unchanged. Not used in mock mode.
      // The JSON API, and the two server-side halves of the sign-in (the redirect to
      // the identity provider and the callback it returns to).
      '/account/api': {
        target: process.env.CANVAS_MCP_DEV_PROXY_TARGET || 'http://127.0.0.1:8819',
        changeOrigin: false,
      },
      '/account/login': {
        target: process.env.CANVAS_MCP_DEV_PROXY_TARGET || 'http://127.0.0.1:8819',
        changeOrigin: false,
      },
      '/account/callback': {
        target: process.env.CANVAS_MCP_DEV_PROXY_TARGET || 'http://127.0.0.1:8819',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    target: 'es2022',
    // No data: URIs for JS/CSS-referenced assets; `img-src 'self' data:` stays a
    // courtesy and nothing in the bundle depends on it.
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (/[\/](react|react-dom|react-router|scheduler)[\/]/.test(id)) return 'vendor-react'
          if (/[\/](@mui|@emotion)[\/]/.test(id)) return 'vendor-mui'
        },
      },
    },
  },
}))
