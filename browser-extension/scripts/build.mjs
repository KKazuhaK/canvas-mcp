// Builds the extension for Chrome (dist/chrome) or Firefox (dist/firefox).
import { build } from 'esbuild';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const target = process.argv[2] === 'firefox' ? 'firefox' : 'chrome';
const out = join(root, 'dist', target);

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const common = { bundle: true, platform: 'browser', legalComments: 'none', logLevel: 'warning' };
const esTarget = target === 'firefox' ? 'firefox142' : 'chrome120';

// The Chrome service worker is an ES module; Firefox runs a classic background script.
await build({ ...common, entryPoints: [join(root, 'src/background.ts')], outfile: join(out, 'background.js'), format: target === 'firefox' ? 'iife' : 'esm', target: esTarget });
await build({ ...common, entryPoints: [join(root, 'src/popup/popup.ts')], outfile: join(out, 'popup.js'), format: 'esm', target: esTarget });
// Injected with scripting.executeScript({files}), so it must be a classic script.
await build({ ...common, entryPoints: [join(root, 'src/link.ts')], outfile: join(out, 'link.js'), format: 'iife', target: esTarget });

await copyFile(join(root, 'src/popup/popup.html'), join(out, 'popup.html'));
await copyFile(join(root, 'src/popup/popup.css'), join(out, 'popup.css'));
await mkdir(join(out, 'icons'));
for (const size of [16, 32, 48, 128]) {
  await copyFile(join(root, `src/icons/icon-${size}.png`), join(out, `icons/icon-${size}.png`));
}

const manifest = JSON.parse(await readFile(join(root, 'src/manifest.json'), 'utf8'));
// Release builds stamp the release version (x.y.z, from the v* tag) into the manifest.
if (process.env.EXTENSION_VERSION) {
  if (!/^(0|[1-9]\d{0,4})(\.(0|[1-9]\d{0,4})){2}$/.test(process.env.EXTENSION_VERSION)) {
    throw new Error(`EXTENSION_VERSION must be x.y.z, got ${process.env.EXTENSION_VERSION}`);
  }
  manifest.version = process.env.EXTENSION_VERSION;
}
if (target === 'firefox') {
  manifest.background = { scripts: ['background.js'] };
  delete manifest.minimum_chrome_version;
  manifest.browser_specific_settings = {
    gecko: {
      id: process.env.CANVAS_SYNC_FIREFOX_ADDON_ID || 'canvas-mcp-sync@canvas-mcp.invalid',
      strict_min_version: '142.0',
      // Course data (websiteContent), the profile's name and email (personallyIdentifyingInfo),
      // Inbox previews in the activity stream (personalCommunications) and the portal upload
      // token (authenticationInfo) leave the page.
      data_collection_permissions: {
        required: ['authenticationInfo', 'personallyIdentifyingInfo', 'personalCommunications', 'websiteContent'],
      },
    },
  };
}
await writeFile(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Built ${target} extension in ${out}`);
