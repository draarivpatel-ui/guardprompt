#!/usr/bin/env node

import { createReadStream } from 'node:fs';
import process from 'node:process';
import { DEFAULT_LIMITS, inspectPrompt, inspectOutput, VERSION } from '../src/index.mjs';

function usage() {
  process.stderr.write([
    'guardprompt ' + VERSION,
    '',
    'Usage:',
    '  guardprompt [--output] [--json] [file]',
    '',
    'Reads standard input when no file is given. Exit codes:',
    '  0 allow, 1 warn, 2 block, 64 usage or input error',
    ''
  ].join('\n'));
}

function parseArgs(argv) {
  const parsed = { output: false, json: false, file: null };
  for (const arg of argv) {
    if (arg === '--output') parsed.output = true;
    else if (arg === '--json') parsed.json = true;
    else if (arg === '--help' || arg === '-h') parsed.help = true;
    else if (arg === '--version') parsed.version = true;
    else if (!arg.startsWith('-') && parsed.file === null) parsed.file = arg;
    else throw new Error('unknown argument: ' + arg);
  }
  return parsed;
}

const MAX_CLI_INPUT_BYTES = DEFAULT_LIMITS.maxInputLength * 4 + 4;

async function readStreamBounded(stream, noun) {
  const chunks = [];
  let total = 0;
  for await (const chunk of stream) {
    total += chunk.length;
    if (total > MAX_CLI_INPUT_BYTES) throw new Error(noun + ' exceeds the bounded CLI input byte limit');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function readStdin() {
  return readStreamBounded(process.stdin, 'standard input');
}

async function readFileBounded(file) {
  return readStreamBounded(createReadStream(file), 'input file');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage();
    return 0;
  }
  if (args.version) {
    process.stdout.write(VERSION + '\n');
    return 0;
  }
  const text = args.file ? await readFileBounded(args.file) : await readStdin();
  const report = args.output ? inspectOutput(text) : inspectPrompt(text);
  if (args.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(report.action + ' risk=' + report.riskScore + ' findings=' + report.findingCount + '\n');
    for (const finding of report.findings.slice(0, 10)) {
      process.stdout.write(finding.id + ' ' + finding.severity + ' ' + finding.description + '\n');
    }
  }
  if (report.action === 'block') return 2;
  if (report.action === 'warn') return 1;
  return 0;
}

main().then((code) => {
  process.exitCode = code;
}).catch((error) => {
  process.stderr.write((error && error.message ? error.message : String(error)) + '\n');
  usage();
  process.exitCode = 64;
});
