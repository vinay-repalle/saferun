import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// A static site: `npm run build` writes web/dist, which any static host can serve (for example Cloudflare Pages).
export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', port: 5173 },
  build: { outDir: 'dist', sourcemap: false, assetsInlineLimit: 0 },
  test: { environment: 'jsdom', globals: true, include: ['src/**/*.test.{js,jsx}'], setupFiles: ['src/test-setup.js'] },
})
