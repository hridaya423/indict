import { defineConfig } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIXTURE = mkdtempSync(join(tmpdir(), 'indict-board-'))
execFileSync('uv', ['run', 'python', 'tests/fixture_board.py', FIXTURE],
  { cwd: join(HERE, '..'), stdio: 'inherit' })

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  reporter: [['list']],
  webServer: {
    command: `uv run python -c "from indictment.board import serve; serve('${FIXTURE}', 8700)"`,
    cwd: join(HERE, '..'),
    url: 'http://127.0.0.1:8700/api/v1/overview',
    // never accept whichever service happens to sit on the port — a foreign
    // server's fixture identity can't be verified, so fail instead
    reuseExistingServer: false,
    timeout: 20_000,
  },
  projects: [
    {
      name: 'e2e',
      testMatch: 'e2e.spec.ts',
      use: { baseURL: 'http://127.0.0.1:8700', viewport: { width: 1536, height: 1024 } },
    },
    {
      name: 'visual',
      testMatch: 'visual.spec.ts',
      use: { baseURL: 'http://127.0.0.1:8700' },
    },
  ],
})
