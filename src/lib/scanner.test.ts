import { describe, it, expect } from 'vitest';
import { scanCode, SAMPLE_VULNERABLE_CODE } from './scanner';

describe('scanCode', () => {
  it('returns a valid ScanResult structure', () => {
    const result = scanCode('const x = 1;');
    expect(result).toHaveProperty('id');
    expect(result).toHaveProperty('timestamp');
    expect(result).toHaveProperty('vulnerabilities');
    expect(result).toHaveProperty('summary');
    expect(result).toHaveProperty('improvements');
    expect(result).toHaveProperty('score');
  });

  it('finds no vulnerabilities in clean code', () => {
    const clean = `
      const express = require('express');
      const app = express();
      app.get('/hello', (_req, res) => res.json({ message: 'Hello World' }));
    `;
    const result = scanCode(clean);
    expect(result.summary.total).toBe(0);
    expect(result.score).toBe(100);
  });

  it('detects innerHTML XSS', () => {
    const code = `document.getElementById('out').innerHTML = userInput;`;
    const result = scanCode(code);
    const xss = result.vulnerabilities.find((v) => v.id.startsWith('xss-innerhtml'));
    expect(xss).toBeDefined();
    expect(xss?.severity).toBe('critical');
    expect(xss?.category).toBe('XSS');
  });

  it('detects eval() injection', () => {
    const code = `eval(userCode);`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('xss-eval'));
    expect(vuln).toBeDefined();
    expect(vuln?.severity).toBe('critical');
  });

  it('detects document.write XSS', () => {
    const code = `document.write('<p>' + input + '</p>');`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('xss-document-write'));
    expect(vuln).toBeDefined();
  });

  it('detects SQL injection via string concatenation', () => {
    const code = `const q = "SELECT * FROM users WHERE id = " + req.query.id;`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('sqli-string-concat'));
    expect(vuln).toBeDefined();
    expect(vuln?.severity).toBe('critical');
    expect(vuln?.cwe).toBe('CWE-89');
  });

  it('detects SQL injection via template literal', () => {
    const code = 'const q = `SELECT * FROM users WHERE id = ${req.params.id}`;';
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('sqli-template-literal'));
    expect(vuln).toBeDefined();
  });

  it('detects hardcoded password', () => {
    const code = `const password = "hunter2abc";`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('hardcoded-secret-password'));
    expect(vuln).toBeDefined();
    expect(vuln?.severity).toBe('high');
  });

  it('detects hardcoded JWT secret', () => {
    const code = `const token = jwt.sign({ id: user.id }, "my-hardcoded-secret-key");`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('hardcoded-jwt-secret'));
    expect(vuln).toBeDefined();
    expect(vuln?.severity).toBe('critical');
  });

  it('detects command injection', () => {
    const code = `exec('ping -c 1 ' + req.body.host, cb);`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('cmdi-exec'));
    expect(vuln).toBeDefined();
    expect(vuln?.severity).toBe('critical');
  });

  it('detects weak MD5 hash', () => {
    const code = `crypto.createHash('md5').update(password).digest('hex');`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('weak-hash-md5'));
    expect(vuln).toBeDefined();
  });

  it('detects wildcard CORS', () => {
    const code = `res.setHeader('Access-Control-Allow-Origin', '*');`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('cors-wildcard'));
    expect(vuln).toBeDefined();
  });

  it('detects dangerouslySetInnerHTML', () => {
    const code = `<div dangerouslySetInnerHTML={{ __html: content }} />`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('react-dangerous-html'));
    expect(vuln).toBeDefined();
  });

  it('detects TLS verification disabled', () => {
    const code = `const agent = new https.Agent({ rejectUnauthorized: false });`;
    const result = scanCode(code);
    const vuln = result.vulnerabilities.find((v) => v.id.startsWith('ssl-verify-disabled'));
    expect(vuln).toBeDefined();
    expect(vuln?.severity).toBe('high');
  });

  it('computes lower score for more vulnerabilities', () => {
    const clean = scanCode('const x = 1;');
    const vulnerable = scanCode(SAMPLE_VULNERABLE_CODE);
    expect(vulnerable.score).toBeLessThan(clean.score);
  });

  it('score is clamped between 0 and 100', () => {
    const result = scanCode(SAMPLE_VULNERABLE_CODE);
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it('always returns improvements', () => {
    const result = scanCode('const x = 1;');
    expect(result.improvements.length).toBeGreaterThan(0);
  });

  it('correctly counts severity summary', () => {
    const result = scanCode(SAMPLE_VULNERABLE_CODE);
    const { summary, vulnerabilities } = result;
    expect(summary.total).toBe(vulnerabilities.length);
    expect(summary.critical).toBe(vulnerabilities.filter((v) => v.severity === 'critical').length);
    expect(summary.high).toBe(vulnerabilities.filter((v) => v.severity === 'high').length);
  });

  it('includes line numbers for each vulnerability', () => {
    const result = scanCode(`eval(x);\neval(y);`);
    result.vulnerabilities.forEach((v) => {
      expect(v.lineNumbers.length).toBeGreaterThan(0);
      expect(v.lineNumbers[0]).toBeGreaterThan(0);
    });
  });

  it('each vulnerability has fix and references', () => {
    const result = scanCode(SAMPLE_VULNERABLE_CODE);
    result.vulnerabilities.forEach((v) => {
      expect(v.fix.length).toBeGreaterThan(0);
      expect(v.references.length).toBeGreaterThan(0);
    });
  });
});
