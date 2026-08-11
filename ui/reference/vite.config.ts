import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'DIRECTOR_UI_');
  return {
    server: {
      host: '127.0.0.1',
      port: 4173,
      proxy: {
        '/api': {
          target: env.DIRECTOR_UI_API_TARGET ?? 'http://127.0.0.1:8444',
          changeOrigin: true,
        },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
    },
  };
});
