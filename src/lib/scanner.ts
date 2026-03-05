import type { ScanRule, Vulnerability, ScanResult, ScanSummary, Improvement } from '../types';

// ─── Security Rules ────────────────────────────────────────────────────────────

const RULES: ScanRule[] = [
  // XSS
  {
    id: 'xss-innerhtml',
    name: 'Cross-Site Scripting via innerHTML',
    description: 'Directly assigning user-controlled data to innerHTML allows attackers to inject malicious scripts that execute in the victim\'s browser.',
    severity: 'critical',
    category: 'XSS',
    pattern: /\.innerHTML\s*=\s*[^'"`;]{0,120}/g,
    fix: 'Use textContent instead of innerHTML when inserting plain text. For HTML rendering, sanitize with DOMPurify: `element.innerHTML = DOMPurify.sanitize(userInput)`.',
    references: ['https://owasp.org/www-community/attacks/xss/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
    cwe: 'CWE-79',
    owasp: 'A03:2021',
  },
  {
    id: 'xss-outerhtml',
    name: 'Cross-Site Scripting via outerHTML',
    description: 'Setting outerHTML with untrusted data enables script injection attacks.',
    severity: 'critical',
    category: 'XSS',
    pattern: /\.outerHTML\s*=\s*/g,
    fix: 'Avoid outerHTML with user data. Use safe DOM methods like createElement/appendChild, or sanitize with DOMPurify.',
    references: ['https://owasp.org/www-community/attacks/xss/'],
    cwe: 'CWE-79',
    owasp: 'A03:2021',
  },
  {
    id: 'xss-document-write',
    name: 'Cross-Site Scripting via document.write',
    description: 'document.write() with unsanitized input is a classic XSS vector that can overwrite the entire page.',
    severity: 'critical',
    category: 'XSS',
    pattern: /document\.write\s*\(/g,
    fix: 'Replace document.write() with safe DOM manipulation methods like document.createElement() and appendChild().',
    references: ['https://developer.mozilla.org/en-US/docs/Web/API/Document/write'],
    cwe: 'CWE-79',
    owasp: 'A03:2021',
  },
  {
    id: 'xss-eval',
    name: 'Code Injection via eval()',
    description: 'eval() executes arbitrary JavaScript strings, allowing attackers to run malicious code if they control any part of the input.',
    severity: 'critical',
    category: 'Injection',
    pattern: /\beval\s*\(/g,
    fix: 'Never use eval(). Parse JSON with JSON.parse(), use Function constructors only with trusted static code, and consider safer alternatives for dynamic behavior.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'],
    cwe: 'CWE-95',
    owasp: 'A03:2021',
  },
  {
    id: 'xss-settimeout-string',
    name: 'Code Injection via setTimeout/setInterval with string argument',
    description: 'Passing a string to setTimeout or setInterval is equivalent to eval() and can execute injected code.',
    severity: 'high',
    category: 'Injection',
    pattern: /set(?:Timeout|Interval)\s*\(\s*['"`]/g,
    fix: 'Pass a function reference to setTimeout/setInterval instead of a string: `setTimeout(() => doSomething(), 1000)`.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/API/setTimeout'],
    cwe: 'CWE-95',
    owasp: 'A03:2021',
  },
  // SQL Injection
  {
    id: 'sqli-string-concat',
    name: 'SQL Injection via String Concatenation',
    description: 'Building SQL queries by concatenating user input allows attackers to manipulate query logic, bypass authentication, or exfiltrate data.',
    severity: 'critical',
    category: 'SQL Injection',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.*?\+\s*(?:req\.|request\.|params\.|body\.|query\.|user)/gi,
    fix: 'Use parameterized queries or prepared statements: `db.query("SELECT * FROM users WHERE id = ?", [userId])`. Never interpolate user input directly into SQL.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
    cwe: 'CWE-89',
    owasp: 'A03:2021',
  },
  {
    id: 'sqli-template-literal',
    name: 'SQL Injection via Template Literal',
    description: 'Interpolating variables directly into SQL template literals is vulnerable to injection if the variable contains user-controlled data.',
    severity: 'critical',
    category: 'SQL Injection',
    pattern: /`\s*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*?\$\{/gi,
    fix: 'Use parameterized queries. For ORMs, use their built-in query builders instead of raw SQL with interpolation.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
    cwe: 'CWE-89',
    owasp: 'A03:2021',
  },
  // Command Injection
  {
    id: 'cmdi-exec',
    name: 'Command Injection via exec/execSync',
    description: 'Passing user input to shell execution functions allows attackers to run arbitrary system commands.',
    severity: 'critical',
    category: 'Command Injection',
    pattern: /(?:exec|execSync|spawn|spawnSync|execFile)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)/g,
    fix: 'Avoid shell commands with user input. If necessary, use execFile() with an array of arguments (no shell), validate input against a strict allowlist, and never use exec() with user-controlled strings.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
    cwe: 'CWE-78',
    owasp: 'A03:2021',
  },
  // Path Traversal
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    description: 'Using user-supplied input in file system paths without sanitization allows attackers to access files outside the intended directory.',
    severity: 'high',
    category: 'Path Traversal',
    pattern: /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|mkdir)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)/g,
    fix: 'Resolve the absolute path with path.resolve() and verify it starts with the expected base directory: `if (!resolvedPath.startsWith(baseDir)) throw new Error("Access denied")`.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'],
    cwe: 'CWE-22',
    owasp: 'A01:2021',
  },
  // Hardcoded Secrets
  {
    id: 'hardcoded-secret-password',
    name: 'Hardcoded Password / Secret',
    description: 'Embedding credentials or secrets directly in source code exposes them to anyone with code access (version history, logs, etc.).',
    severity: 'high',
    category: 'Sensitive Data Exposure',
    pattern: /(?:password|passwd|secret|api_key|apikey|auth_token|access_token)\s*[:=]\s*['"][^'"]{4,}/gi,
    fix: 'Store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Access via process.env.SECRET_NAME and never commit .env files.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
    cwe: 'CWE-798',
    owasp: 'A07:2021',
  },
  {
    id: 'hardcoded-jwt-secret',
    name: 'Hardcoded JWT Secret',
    description: 'A hardcoded JWT secret allows anyone with the secret to forge authentication tokens for any user.',
    severity: 'critical',
    category: 'Broken Authentication',
    pattern: /jwt\.sign\s*\([^,]+,\s*['"][^'"]{4,}['"]/g,
    fix: 'Load the JWT secret from an environment variable: `jwt.sign(payload, process.env.JWT_SECRET, options)`. Rotate the secret if it has been exposed.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
    cwe: 'CWE-798',
    owasp: 'A07:2021',
  },
  // Insecure Configurations
  {
    id: 'cors-wildcard',
    name: 'Overly Permissive CORS Policy',
    description: 'Setting Access-Control-Allow-Origin to "*" with credentials allows any website to make authenticated requests on behalf of the user.',
    severity: 'high',
    category: 'Security Misconfiguration',
    pattern: /Access-Control-Allow-Origin['",:)\s]*\*|cors\s*\(\s*\{\s*origin\s*:\s*['"`]\*['"`]/g,
    fix: 'Specify exact allowed origins: `cors({ origin: process.env.ALLOWED_ORIGIN })`. Never combine wildcard origin with `credentials: true`.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
    cwe: 'CWE-942',
    owasp: 'A05:2021',
  },
  {
    id: 'ssl-verify-disabled',
    name: 'SSL/TLS Certificate Verification Disabled',
    description: 'Disabling TLS verification makes the application vulnerable to man-in-the-middle attacks that can intercept encrypted traffic.',
    severity: 'high',
    category: 'Security Misconfiguration',
    pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/g,
    fix: 'Never disable certificate verification in production. Fix the root cause (install proper certificates). For testing, use a local CA instead.',
    references: ['https://nodejs.org/api/tls.html'],
    cwe: 'CWE-295',
    owasp: 'A05:2021',
  },
  {
    id: 'debug-mode',
    name: 'Debug Mode Enabled in Production',
    description: 'Running with debug mode or verbose error messages in production leaks internal application details to attackers.',
    severity: 'medium',
    category: 'Security Misconfiguration',
    pattern: /debug\s*:\s*true|NODE_ENV\s*!==?\s*['"]production['"].*?debug/g,
    fix: 'Disable debug mode in production. Use environment-specific configuration and ensure NODE_ENV=production in production deployments.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html'],
    cwe: 'CWE-489',
    owasp: 'A05:2021',
  },
  // Authentication Issues
  {
    id: 'weak-hash-md5',
    name: 'Weak Cryptographic Hash (MD5)',
    description: 'MD5 is cryptographically broken and should never be used for password hashing or security-sensitive operations.',
    severity: 'high',
    category: 'Cryptography',
    pattern: /(?:createHash|md5)\s*\(\s*['"]md5['"]/gi,
    fix: 'Use bcrypt, argon2, or scrypt for passwords. For data integrity, use SHA-256 or stronger: `crypto.createHash("sha256")`.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'],
    cwe: 'CWE-327',
    owasp: 'A02:2021',
  },
  {
    id: 'weak-hash-sha1',
    name: 'Weak Cryptographic Hash (SHA-1)',
    description: 'SHA-1 is considered cryptographically weak and vulnerable to collision attacks.',
    severity: 'medium',
    category: 'Cryptography',
    pattern: /createHash\s*\(\s*['"]sha1['"]/gi,
    fix: 'Upgrade to SHA-256 or SHA-3: `crypto.createHash("sha256")`. For passwords, use bcrypt or argon2 instead of any plain hash.',
    references: ['https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf'],
    cwe: 'CWE-327',
    owasp: 'A02:2021',
  },
  {
    id: 'missing-auth-check',
    name: 'Missing Authorization Check',
    description: 'Route handlers that modify data without checking if the user has permission to do so are vulnerable to unauthorized access.',
    severity: 'high',
    category: 'Broken Access Control',
    pattern: /(?:app|router)\s*\.(?:post|put|patch|delete)\s*\([^)]+\)\s*,?\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{(?![\s\S]*?(?:auth|authorize|isAuthenticated|requiresAuth|middleware|checkPermission))/g,
    fix: 'Add authentication middleware to protected routes: `router.post("/resource", authenticate, authorize("admin"), handler)`. Check ownership before allowing modifications.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'],
    cwe: 'CWE-862',
    owasp: 'A01:2021',
  },
  // React-specific
  {
    id: 'react-dangerous-html',
    name: 'Dangerous HTML Injection in React',
    description: 'dangerouslySetInnerHTML bypasses React\'s XSS protections. Unsanitized HTML can execute malicious scripts.',
    severity: 'high',
    category: 'XSS',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    fix: 'Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML: `{ __html: DOMPurify.sanitize(htmlContent) }`. Consider using libraries like react-markdown for rendering markdown.',
    references: ['https://react.dev/reference/react-dom/components/common#dangerouslysetinnerhtml'],
    cwe: 'CWE-79',
    owasp: 'A03:2021',
  },
  {
    id: 'react-href-js',
    name: 'JavaScript URL in href',
    description: 'Using javascript: URLs in href attributes allows XSS when the link is clicked.',
    severity: 'high',
    category: 'XSS',
    pattern: /href\s*=\s*\{[^}]*\}\s*(?=[^>]*>)|href\s*=\s*['"]javascript:/gi,
    fix: 'Validate URLs before using them in href. Use a URL allowlist or ensure the URL starts with https://: `if (!url.startsWith("https://")) return "#"`.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-2-attribute-encode-before-inserting-untrusted-data-into-html-common-attributes'],
    cwe: 'CWE-79',
    owasp: 'A03:2021',
  },
  // Prototype Pollution
  {
    id: 'prototype-pollution',
    name: 'Prototype Pollution Risk',
    description: 'Deep merging or copying objects with user-controlled keys like __proto__ or constructor can pollute the Object prototype.',
    severity: 'high',
    category: 'Injection',
    pattern: /\[.*?(?:__proto__|constructor|prototype).*?\]\s*=/g,
    fix: 'Use Object.create(null) for dictionaries, validate merge targets, use libraries like lodash that protect against prototype pollution, or use JSON.parse/stringify for deep cloning.',
    references: ['https://learn.snyk.io/lesson/prototype-pollution/'],
    cwe: 'CWE-1321',
    owasp: 'A08:2021',
  },
  // Open Redirect
  {
    id: 'open-redirect',
    name: 'Open Redirect',
    description: 'Redirecting users to URLs from request parameters without validation can facilitate phishing attacks.',
    severity: 'medium',
    category: 'Open Redirect',
    pattern: /res\.redirect\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)/g,
    fix: 'Validate redirect URLs against an allowlist of trusted domains. Use relative paths for internal redirects: `res.redirect("/dashboard")` instead of user-supplied URLs.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
    cwe: 'CWE-601',
    owasp: 'A01:2021',
  },
  // Mass Assignment
  {
    id: 'mass-assignment',
    name: 'Mass Assignment Vulnerability',
    description: 'Directly assigning all request body fields to a model can allow attackers to set privileged fields like isAdmin or role.',
    severity: 'high',
    category: 'Broken Access Control',
    pattern: /(?:Object\.assign|spread operator|\.\.\.).*?(?:req\.body|request\.body)/g,
    fix: 'Explicitly pick only the allowed fields from the request body: `const { name, email } = req.body`. Use an allowlist or schema validation library like Joi or Zod.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html'],
    cwe: 'CWE-915',
    owasp: 'A03:2021',
  },
  // Session Issues
  {
    id: 'insecure-cookie',
    name: 'Insecure Cookie Configuration',
    description: 'Cookies without Secure, HttpOnly, and SameSite flags are vulnerable to theft via XSS or network interception.',
    severity: 'medium',
    category: 'Session Management',
    pattern: /res\.cookie\s*\([^)]*\)(?![\s\S]*?(?:httpOnly|secure|sameSite))/g,
    fix: 'Set all security flags on cookies: `res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 3600000 })`.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'],
    cwe: 'CWE-1004',
    owasp: 'A07:2021',
  },
  // SSRF
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Making HTTP requests to user-supplied URLs allows attackers to target internal services, cloud metadata endpoints, or bypass firewalls.',
    severity: 'high',
    category: 'SSRF',
    pattern: /(?:fetch|axios\.get|axios\.post|http\.get|https\.get|request)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)/g,
    fix: 'Validate URLs against an allowlist of permitted domains. Block requests to private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x, 169.254.x.x) and localhost.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'],
    cwe: 'CWE-918',
    owasp: 'A10:2021',
  },
  // XXE
  {
    id: 'xxe',
    name: 'XML External Entity (XXE) Injection',
    description: 'Parsing XML from untrusted sources with external entity processing enabled can leak files, SSRF, or cause DoS.',
    severity: 'high',
    category: 'XXE',
    pattern: /(?:parseXML|DOMParser|xml2js|xmldom|sax).*?(?:req\.|request\.|body|input)/gi,
    fix: 'Disable external entity processing in your XML parser. For xml2js: `{ explicitCharkey: false }`. Consider switching to JSON APIs where possible.',
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'],
    cwe: 'CWE-611',
    owasp: 'A05:2021',
  },
];

// ─── Improvement Suggestions ───────────────────────────────────────────────────

const IMPROVEMENT_TEMPLATES: Improvement[] = [
  {
    id: 'imp-csp',
    title: 'Add Content Security Policy (CSP) Header',
    description: 'A Content Security Policy prevents XSS by controlling which resources the browser is allowed to load.',
    category: 'Defense in Depth',
    priority: 'high',
    example: `// Express.js with helmet\nconst helmet = require('helmet');\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc: ["'self'"],\n    styleSrc: ["'self'", "'unsafe-inline'"],\n    imgSrc: ["'self'", 'data:', 'https:'],\n  },\n}));`,
    benefit: 'Blocks XSS attacks even if sanitization is bypassed, drastically reducing attack surface.',
  },
  {
    id: 'imp-rate-limit',
    title: 'Implement Rate Limiting',
    description: 'Rate limiting prevents brute-force attacks on login, API abuse, and denial-of-service attacks.',
    category: 'Availability',
    priority: 'high',
    example: `// express-rate-limit\nconst rateLimit = require('express-rate-limit');\nconst limiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 100,\n  message: 'Too many requests',\n});\napp.use('/api/', limiter);`,
    benefit: 'Prevents brute force, credential stuffing, and API abuse attacks.',
  },
  {
    id: 'imp-input-validation',
    title: 'Add Schema-Based Input Validation',
    description: 'Validate all incoming data against a strict schema using Zod or Joi to reject malformed or malicious input early.',
    category: 'Input Validation',
    priority: 'high',
    example: `// Using Zod\nimport { z } from 'zod';\nconst UserSchema = z.object({\n  email: z.string().email(),\n  age: z.number().int().min(0).max(120),\n  name: z.string().max(100),\n});\nconst user = UserSchema.parse(req.body); // throws on invalid`,
    benefit: 'Rejects malicious input before it reaches business logic or the database.',
  },
  {
    id: 'imp-security-headers',
    title: 'Set Security HTTP Headers',
    description: 'Security headers like X-Frame-Options, X-Content-Type-Options, and HSTS protect against common browser-based attacks.',
    category: 'Defense in Depth',
    priority: 'high',
    example: `// Use helmet.js in Express\nconst helmet = require('helmet');\napp.use(helmet()); // Sets 11 security headers automatically`,
    benefit: 'Mitigates clickjacking, MIME sniffing, and protocol downgrade attacks.',
  },
  {
    id: 'imp-mfa',
    title: 'Implement Multi-Factor Authentication',
    description: 'MFA adds a critical second layer of authentication, preventing account takeovers even when passwords are compromised.',
    category: 'Authentication',
    priority: 'high',
    example: `// TOTP with otpauth library\nimport * as OTPAuth from 'otpauth';\nconst totp = new OTPAuth.TOTP({\n  issuer: 'MyApp',\n  label: user.email,\n  algorithm: 'SHA1',\n  digits: 6,\n  secret: user.mfaSecret,\n});\nconst isValid = totp.validate({ token: userProvidedCode }) !== null;`,
    benefit: 'Prevents 99.9% of account compromise attacks according to Microsoft research.',
  },
  {
    id: 'imp-logging',
    title: 'Implement Security Audit Logging',
    description: 'Log security-relevant events (logins, failures, admin actions) to detect attacks and support incident response.',
    category: 'Monitoring',
    priority: 'medium',
    example: `// Structured security logging\nlogger.warn({\n  event: 'LOGIN_FAILURE',\n  userId: req.body.email,\n  ip: req.ip,\n  userAgent: req.headers['user-agent'],\n  timestamp: new Date().toISOString(),\n});`,
    benefit: 'Enables detection of attacks in progress and forensic analysis after incidents.',
  },
  {
    id: 'imp-dependency-audit',
    title: 'Automate Dependency Vulnerability Scanning',
    description: 'Regularly audit npm dependencies for known CVEs using npm audit or Snyk in your CI pipeline.',
    category: 'Supply Chain Security',
    priority: 'medium',
    example: `# In CI/CD pipeline\nnpm audit --audit-level=high\n# Or use Snyk\nsnyk test --severity-threshold=high`,
    benefit: 'Catches known vulnerabilities in third-party packages before they reach production.',
  },
  {
    id: 'imp-csrf',
    title: 'Add CSRF Protection',
    description: 'CSRF tokens prevent attackers from tricking authenticated users into making unintended state-changing requests.',
    category: 'Session Management',
    priority: 'medium',
    example: `// csurf middleware (or use SameSite cookies)\nconst csrf = require('csurf');\napp.use(csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } }));\napp.get('/form', (req, res) => {\n  res.render('form', { csrfToken: req.csrfToken() });\n});`,
    benefit: 'Prevents cross-site request forgery attacks that can perform actions on behalf of logged-in users.',
  },
  {
    id: 'imp-error-handling',
    title: 'Implement Secure Error Handling',
    description: 'Never expose stack traces, database errors, or internal paths in error responses to clients.',
    category: 'Information Disclosure',
    priority: 'medium',
    example: `// Express global error handler\napp.use((err: Error, req: Request, res: Response, _next: NextFunction) => {\n  logger.error(err); // Log full details server-side\n  res.status(500).json({ error: 'Internal server error' }); // Generic message to client\n});`,
    benefit: 'Prevents information leakage that attackers use to tailor their attacks.',
  },
  {
    id: 'imp-https',
    title: 'Enforce HTTPS with HSTS',
    description: 'HTTP Strict Transport Security ensures browsers always connect via HTTPS, preventing downgrade attacks.',
    category: 'Transport Security',
    priority: 'high',
    example: `// In helmet.js\napp.use(helmet.hsts({\n  maxAge: 31536000, // 1 year in seconds\n  includeSubDomains: true,\n  preload: true,\n}));`,
    benefit: 'Prevents man-in-the-middle attacks via protocol downgrade and cookie theft over HTTP.',
  },
];

// ─── Scanner Logic ─────────────────────────────────────────────────────────────

function getLineNumbers(source: string, matchIndex: number): number[] {
  const lines = source.substring(0, matchIndex).split('\n');
  return [lines.length];
}

function computeScore(summary: ScanSummary): number {
  const penalty = summary.critical * 25 + summary.high * 15 + summary.medium * 8 + summary.low * 3 + summary.info * 1;
  return Math.max(0, 100 - penalty);
}

function selectImprovements(): Improvement[] {
  return [...IMPROVEMENT_TEMPLATES];
}

export function scanCode(source: string): ScanResult {
  const vulnerabilities: Vulnerability[] = [];

  for (const rule of RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(source)) !== null) {
      const lineNumbers = getLineNumbers(source, match.index);
      const snippet = source.substring(
        Math.max(0, match.index - 40),
        Math.min(source.length, match.index + match[0].length + 40),
      ).replace(/\n/g, ' ');

      vulnerabilities.push({
        id: `${rule.id}-${match.index}`,
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        category: rule.category,
        lineNumbers,
        snippet: snippet.trim(),
        fix: rule.fix,
        references: rule.references,
        cwe: rule.cwe,
        owasp: rule.owasp,
      });

      // Prevent infinite loops on zero-length matches
      if (match.index === regex.lastIndex) {
        regex.lastIndex++;
      }
    }
  }

  const summary: ScanSummary = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
    info: vulnerabilities.filter((v) => v.severity === 'info').length,
  };

  const score = computeScore(summary);
  const improvements = selectImprovements();

  return {
    id: crypto.randomUUID(),
    timestamp: new Date(),
    sourceCode: source,
    vulnerabilities,
    summary,
    improvements,
    score,
  };
}

export const SAMPLE_VULNERABLE_CODE = `// ⚠️  SAMPLE VULNERABLE WEB APP CODE - DO NOT USE IN PRODUCTION
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ❌ Hardcoded secret
const DB_PASSWORD = "supersecret123";
const JWT_SECRET = "my-secret-key";

// ❌ No rate limiting, no CORS config

// ❌ SQL Injection
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query, (err, result) => res.json(result));
});

// ❌ Command Injection
app.post('/ping', (req, res) => {
  exec('ping -c 1 ' + req.body.host, (err, stdout) => {
    res.send(stdout);
  });
});

// ❌ Broken Auth - hardcoded JWT secret
app.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.username }, "my-secret-key");
  res.cookie('token', token);
});

// ❌ Path Traversal
app.get('/file', (req, res) => {
  const content = fs.readFileSync('/app/files/' + req.query.filename);
  res.send(content);
});

// ❌ Open Redirect
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

// ❌ Weak hash for passwords
function hashPassword(pwd) {
  return crypto.createHash('md5').update(pwd).digest('hex');
}

// ❌ XSS in frontend
document.getElementById('output').innerHTML = userInput;
document.write('<p>' + window.location.search + '</p>');
eval(userPayload);

app.listen(3000);
`;
