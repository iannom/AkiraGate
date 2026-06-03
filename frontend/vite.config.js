import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const devSecretPath = process.env.VITE_DEV_SECRET_PATH || "";
const devApiOrigin = process.env.VITE_DEV_API_ORIGIN || "http://127.0.0.1:8787";

export default defineConfig({
  base: "./",
  plugins: [react()],
  server: devSecretPath
    ? {
        proxy: {
          "/api": {
            target: devApiOrigin,
            changeOrigin: true,
            rewrite: (path) => `/${devSecretPath.replace(/^\/|\/$/g, "")}${path}`,
          },
        },
      }
    : undefined,
});
