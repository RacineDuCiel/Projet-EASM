import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // Use modern JavaScript for smaller bundles
    target: 'esnext',
    // Fast minification with esbuild (default)
    minify: 'esbuild',
    // Disable source maps in production for smaller bundles
    sourcemap: false,
    // Split chunks for better caching
    rollupOptions: {
      output: {
        manualChunks: {
          // Core React libraries (rarely change)
          vendor: ['react', 'react-dom', 'react-router-dom'],
          // Charts library (large, lazy loaded)
          charts: ['recharts'],
          // Data fetching layer
          query: ['@tanstack/react-query', 'axios', 'zustand'],
          // UI components
          ui: [
            '@radix-ui/react-dialog',
            '@radix-ui/react-dropdown-menu',
            '@radix-ui/react-select',
            '@radix-ui/react-tabs',
            '@radix-ui/react-toast',
          ],
        },
      },
    },
    // Increase chunk size warning limit (recharts is large)
    chunkSizeWarningLimit: 600,
  },
  // Optimize dependency pre-bundling
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query'],
  },
})
