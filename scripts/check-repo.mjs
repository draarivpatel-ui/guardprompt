import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skipDirectories = new Set(['.git', 'node_modules', '.DS_Store']);
const skipFiles = new Set(['package-lock.json']);
const failures = [];

function walk(directory) {
  for (const entry of readdirSync(directory)) {
    if (skipDirectories.has(entry)) continue;
    const full = path.join(directory, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) walk(full);
    else if (!skipFiles.has(entry)) checkFile(full);
  }
}

function checkFile(file) {
  const buffer = readFileSync(file);
  if (buffer.includes(0)) return;
  const text = buffer.toString('utf8');
  const relative = path.relative(root, file);
  if (text.includes('\u2013') || text.includes('\u2014')) {
    failures.push(relative + ': contains an en dash or em dash');
  }
  if (new RegExp('Co-Authored' + '-By:', 'i').test(text)) {
    failures.push(relative + ': contains a co-author trailer');
  }
}

walk(root);
if (failures.length) {
  for (const failure of failures) process.stderr.write(failure + '\n');
  process.exit(1);
}
process.stdout.write('repository text policy checks passed\n');
