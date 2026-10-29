// Builds the browser bundle and stylesheet:
//   dist/client/sealform.js   one ES module with signature_pad included, for a plain <script type="module">
//   dist/client/sealform.css  compiled from src/client/sealform.scss
// tsc separately emits dist/client/index.js for bundler users.

import { mkdir, writeFile } from 'node:fs/promises';
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

console.log('Built dist/client/sealform.js and dist/client/sealform.css');
