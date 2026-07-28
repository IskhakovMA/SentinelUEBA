import { rmSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(process.cwd(), '..', '.tmp', 'dashboard-smoke');
rmSync(root, { recursive: true, force: true });
mkdirSync(root, { recursive: true });
