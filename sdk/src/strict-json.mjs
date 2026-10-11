// Bounded JSON reader with duplicate-key rejection. No eval or prototype setters.
export function parseStrictJson(text, maxBytes = 131072) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > maxBytes)
    throw new Error('JSON input exceeds its size limit.');
  let i = 0;
  const ws = () => {
    while (/[\x20\t\r\n]/.test(text[i] ?? '\0')) i++;
  };
  function string() {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') return JSON.parse(text.slice(start, i));
      if (c === '\\') i++;
    }
    throw new Error('Unterminated JSON string.');
  }
  function value(depth = 0) {
    if (depth > 12) throw new Error('JSON nesting is too deep.');
    ws();
    if (text[i] === '"') return string();
    if (text[i] === '{') {
      i++;
      ws();
      const result = Object.create(null);
      const seen = new Set();
      if (text[i] === '}') {
        i++;
        return result;
      }
      while (true) {
        ws();
        if (text[i] !== '"') throw new Error('JSON object keys must be strings.');
        const key = string();
        if (seen.has(key)) throw new Error('Duplicate JSON keys are not allowed.');
        seen.add(key);
        ws();
        if (text[i++] !== ':') throw new Error('Expected a JSON colon.');
        result[key] = value(depth + 1);
        ws();
        const end = text[i++];
        if (end === '}') return result;
        if (end !== ',') throw new Error('Expected a JSON comma.');
      }
    }
    if (text[i] === '[') {
      i++;
      ws();
      const result = [];
      if (text[i] === ']') {
        i++;
        return result;
      }
      while (true) {
        result.push(value(depth + 1));
        ws();
        const end = text[i++];
        if (end === ']') return result;
        if (end !== ',') throw new Error('Expected a JSON comma.');
      }
    }
    for (const [word, result] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ]) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return result;
      }
    }
    const number = text.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (number) {
      i += number[0].length;
      const n = Number(number[0]);
      if (!Number.isFinite(n)) throw new Error('Non-finite JSON number.');
      return n;
    }
    throw new Error('Invalid JSON value.');
  }
  const result = value();
  ws();
  if (i !== text.length) throw new Error('Unexpected data after JSON.');
  return result;
}
