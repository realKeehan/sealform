// Builds the browser bundle and stylesheet:
//   dist/client/sealform.js   one ES module with signature_pad included, for a plain <script type="module">
//   dist/client/sealform.css  compiled from src/client/sealform.scss
// tsc separately emits dist/client/index.js for bundler users.

import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import { build } from 'esbuild';
import { compile } from 'sass';

await mkdir('dist/client', { recursive: true });

await build({
  entryPoints: ['src/client/index.ts'],
  outfile: 'dist/client/sealform.js',
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  sourcemap: true,
  legalComments: 'linked',
});

const css = compile('src/client/sealform.scss', { style: 'compressed' });
await writeFile('dist/client/sealform.css', css.css + '\n');

// The admin stylesheet is plain CSS that the server reads next to its own module.
await mkdir('dist/server/admin', { recursive: true });
await copyFile('src/server/admin/admin.css', 'dist/server/admin/admin.css');

console.log('Built dist/client/sealform.js, dist/client/sealform.css and dist/server/admin/admin.css');
