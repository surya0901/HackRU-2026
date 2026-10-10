import { build, context } from 'esbuild';
import { cpSync, mkdirSync } from 'node:fs';

const watch = process.argv.includes('--watch');

// One esbuild graph per extension entry point. Background + content scripts are
// plain TS; popup + side panel are React. Everything is bundled (no remote code,
// MV3-safe) and emitted into dist/ alongside the static manifest/html/icons.
const entryPoints = {
  background: 'src/background/index.ts',
  'content-github': 'src/content/github-overlay.ts',
  'content-pagescan': 'src/content/page-scan.ts',
  popup: 'src/popup/index.tsx',
  sidepanel: 'src/sidepanel/index.tsx',
};

/** @type {import('esbuild').BuildOptions} */
const options = {
  entryPoints,
  bundle: true,
  outdir: 'dist',
  format: 'esm',
  target: ['chrome120'],
  platform: 'browser',
  jsx: 'automatic',
  sourcemap: watch ? 'inline' : false,
  minify: !watch,
  legalComments: 'none',
  define: { 'process.env.NODE_ENV': watch ? '"development"' : '"production"' },
  loader: { '.svg': 'text' },
};

function copyStatic() {
  mkdirSync('dist', { recursive: true });
  // Static assets that ship verbatim into the unpacked extension.
  for (const f of ['manifest.json', 'popup.html', 'sidepanel.html']) {
    cpSync(`public/${f}`, `dist/${f}`);
  }
  cpSync('public/icons', 'dist/icons', { recursive: true });
}

copyStatic();

if (watch) {
  const ctx = await context(options);
  await ctx.watch();
  console.log('esbuild: watching…');
} else {
  await build(options);
  console.log('esbuild: built dist/*.js');
}
