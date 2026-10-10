import { build } from 'esbuild';

await build({
  entryPoints: ['src/index.js'],
  outfile: 'web/core.js',
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  legalComments: 'eof'
});
