import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { viteSingleFile } from 'vite-plugin-singlefile'

// The console is shipped as a single self-contained HTML file so that the Rust
// static-asset layer can embed it with a single include_bytes!. Dev mode still
// serves normal modules.
export default defineConfig({
  base: './',
  plugins: [vue(), viteSingleFile({ removeViteModuleLoader: true })],
  // Dev mode: forward API calls to a locally running eShield (8720).
  // If nothing is listening the client falls back to mock data automatically.
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8720',
      '/metrics': 'http://127.0.0.1:8720',
    },
  },
  build: {
    target: 'es2020',
    cssCodeSplit: false,
    assetsInlineLimit: 100000000,
    chunkSizeWarningLimit: 4096,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
})
