import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],

  // No custom aliases needed when using published package
  // resolve: {
  //   alias: {},
  // },

  // Explicitly include WASM files and compiled FHE programs as assets
  assetsInclude: ["**/*.wasm", "**/fixtures/**"],

  server: {
    port: 5173,
    open: true,
  },

  build: {
    target: "esnext",
    outDir: "dist",
    // Ensure source maps for debugging
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          // Put all libraries from node_modules into a separate 'vendor' chunk
          if (id.includes("node_modules")) {
            return "vendor";
          }
        },
      },
    },
  },

  optimizeDeps: {
    exclude: ["spf-client"],
    esbuildOptions: {
      // Support latest JavaScript features
      target: "esnext",
    },
  },
});
