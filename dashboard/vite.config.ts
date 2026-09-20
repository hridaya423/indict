import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: '../indictment/board_dist',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 400,
  },
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8404' },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
  },
})
