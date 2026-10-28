const esbuild = require('esbuild');
const fs = require('node:fs');
fs.mkdirSync('dist', { recursive: true });
fs.copyFileSync('src/index.html', 'dist/index.html');
esbuild.buildSync({ entryPoints: ['src/app.jsx'], bundle: true, minify: true,
  sourcemap: false, outfile: 'dist/app.js', platform: 'browser', target: 'chrome130',
  loader: { '.svg': 'dataurl' }, define: { 'process.env.NODE_ENV': '"production"' } });
console.log('Desktop interface built.');
