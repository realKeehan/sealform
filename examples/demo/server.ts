// Local demo: `npm run build && npm run demo`, then open http://localhost:5180
// Generates a throwaway key and stores signatures under examples/demo/.data (git-ignored).

import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, KEYSET_FORMAT, type KeySet, type PrivateKeyFile } from '../../src/core/index.ts';
import { createSealform } from '../../src/server/index.ts';

const here = fileURLToPath(new URL('.', import.meta.url));
const root = join(here, '..', '..');
const dataDir = join(here, '.data');
const port = Number(process.env.PORT ?? 5180);
const origin = `http://localhost:${port}`;

await mkdir(dataDir, { recursive: true });
const keyPath = join(dataDir, 'demo.private.jwk.json');
const keysetPath = join(dataDir, 'sealform-keys.json');
if (!existsSync(keyPath)) {
  const { privateFile, publicEntry } = await generateKeyPair('demo');
  await writeFile(keyPath, JSON.stringify(privateFile), { mode: 0o600 });
  await writeFile(keysetPath, JSON.stringify({ format: KEYSET_FORMAT, keys: [publicEntry] } satisfies KeySet));
}

const sealform = await createSealform({
  dataDir,
  documentsDir: join(root, 'test', 'fixtures', 'documents'),
  sealingKey: JSON.parse(await readFile(keyPath, 'utf8')) as PrivateKeyFile,
  keySet: keysetPath,
  publicOrigin: origin,
  operator: { name: 'Demo Studio', email: 'legal@example.com' },
  limits: { signPerWindow: 100 },
});

const files: Record<string, string> = {
  '/': join(here, 'index.html'),
  '/sealform.js': join(root, 'dist', 'client', 'sealform.js'),
  '/sealform.js.map': join(root, 'dist', 'client', 'sealform.js.map'),
  '/sealform.css': join(root, 'dist', 'client', 'sealform.css'),
};
const types: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.map': 'application/json' };

createServer((req, res) => {
  const path = new URL(req.url ?? '/', origin).pathname;
  const file = files[path];
  if (!file) return sealform.handler(req, res);
  readFile(file).then(
    (body) => {
      res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
      res.end(body);
    },
    () => {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('Run `npm run build` first.');
    },
  );
}).listen(port, () => console.log(`sealform demo on ${origin}  (records in ${dataDir})`));
