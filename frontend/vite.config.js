import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'https://threat-intelligence-correlation-engine-3gnf.onrender.com',
        changeOrigin: true,
      }
    }
  }
})

