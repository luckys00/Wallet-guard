import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  css: {
    // Disable Tailwind CSS auto-detection warning (we use vanilla CSS)
    transformer: 'postcss',
  },
})
