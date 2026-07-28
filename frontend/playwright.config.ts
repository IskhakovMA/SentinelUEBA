import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 240_000,
  expect: { timeout: 30_000 },
  use: {
    ...devices['Desktop Chrome'],
    baseURL: 'http://127.0.0.1:5173',
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command:
        'node scripts/prepare-smoke-runtime.mjs && cd .. && SENTINELUEBA_RUNTIME_ROOT=.tmp/dashboard-smoke uv run uvicorn sentinelueba.api.main:app --host 127.0.0.1 --port 8000',
      url: 'http://127.0.0.1:8000/health/ready',
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: 'pnpm dev --host 127.0.0.1',
      url: 'http://127.0.0.1:5173',
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
});
