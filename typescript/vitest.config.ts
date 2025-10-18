import { defineConfig } from 'vitest/config';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  test: {
    // Run tests sequentially to avoid overwhelming the API
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    // Increase timeout for network operations
    testTimeout: 30000,
    hookTimeout: 30000,
    // Show detailed output
    reporters: ['default'],
  },
});
