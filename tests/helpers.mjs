export function tagEncode(text) {
  let output = '';
  for (const ch of text) {
    output += String.fromCodePoint(0xE0000 + ch.codePointAt(0));
  }
  return output;
}

export function cp(codePoint) {
  return String.fromCodePoint(codePoint);
}

export function rot13(text) {
  let output = '';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (code >= 65 && code <= 90) output += String.fromCharCode(((code - 65 + 13) % 26) + 65);
    else if (code >= 97 && code <= 122) output += String.fromCharCode(((code - 97 + 13) % 26) + 97);
    else output += ch;
  }
  return output;
}

export function hexEncode(text) {
  return Buffer.from(text, 'utf8').toString('hex');
}

export function base64Encode(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

export function urlEncodeBytes(text) {
  return Array.from(Buffer.from(text, 'utf8')).map((byte) => '%' + byte.toString(16).padStart(2, '0').toUpperCase()).join('');
}

export function findingIds(result) {
  const list = Array.isArray(result) ? result : result.findings;
  return list.map((finding) => finding.id);
}

export function hasFinding(result, id) {
  return findingIds(result).includes(id);
}

export function deterministicString(seed, length) {
  let state = seed >>> 0;
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;:_-';
  let output = '';
  for (let i = 0; i < length; i += 1) {
    state = (state * 1664525 + 1013904223) >>> 0;
    output += alphabet[state % alphabet.length];
  }
  return output;
}
