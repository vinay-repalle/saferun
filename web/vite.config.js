import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev only: the Vite dev server proxies /api to the loopback SafeRun server. In production the SPA is served by
// the SafeRun server itself (same origin, no CORS), so nothing here is a deployment configuration.
export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173, proxy: {
      // changeOrigin is off so the proxied Host stays the browser's (localhost:5173) and matches its Origin; the
      // string shorthand rewrites Host to the target, which the server's same-origin guard then refuses on uploads.
      '/api': { target: 'http://127.0.0.1:8765', changeOrigin: false },
    },
  },
  build: { outDir: 'dist', sourcemap: false, assetsInlineLimit: 0 },
  test: { environment: 'jsdom', globals: true, include: ['src/**/*.test.{js,jsx}'], setupFiles: ['src/test-setup.js'] },
})
