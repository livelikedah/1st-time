# 🔐 AI Security Analyzer

A **fully autonomous AI-powered web application security scanner** built with React and TypeScript. Paste your JavaScript/TypeScript/Node.js code and get an instant, comprehensive security audit with vulnerability detection, severity ratings, fix suggestions, and improvement recommendations.

## ✨ Features

### 🔍 Autonomous Vulnerability Detection
Detects **23+ vulnerability patterns** covering the OWASP Top 10:

| Category | Vulnerabilities Detected |
|---|---|
| **XSS** | innerHTML, outerHTML, document.write, dangerouslySetInnerHTML, javascript: URLs |
| **Injection** | SQL injection (string concat & template literals), Command injection, eval() |
| **Broken Auth** | Hardcoded JWT secrets, weak hashes (MD5, SHA-1) |
| **Sensitive Data** | Hardcoded passwords, API keys, tokens |
| **Misconfiguration** | Wildcard CORS, TLS verification disabled, debug mode |
| **Access Control** | Path traversal, open redirect, mass assignment |
| **Other** | SSRF, XXE, prototype pollution, insecure cookies |

### 📊 Security Score
- Visual gauge showing your app's security score (0–100)
- Color-coded severity badges (Critical / High / Medium / Low)
- Timestamped scan history

### 🛠️ Fix Suggestions
Every vulnerability comes with:
- Detailed description of the risk
- Line number of the detected issue
- The exact code snippet that triggered the alert
- Step-by-step remediation guidance
- CWE and OWASP references

### 💡 Improvement Ideas
10 best-practice security improvements with code examples:
- Content Security Policy (CSP)
- Rate limiting
- Schema-based input validation
- Security HTTP headers
- Multi-factor authentication
- Audit logging
- CSRF protection
- Dependency vulnerability scanning
- Secure error handling
- HTTPS/HSTS enforcement

## 🚀 Getting Started

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

## 🧪 Testing

20 unit tests covering every vulnerability rule and scanner behavior:

```bash
npm test
```

## 🏗️ Tech Stack

- **React 19** + **TypeScript**
- **Vite** (build tool)
- **Vitest** (testing)
- **ESLint** (linting)
- Zero runtime dependencies beyond React

## ⚠️ Disclaimer

This tool uses static pattern analysis and is intended to complement — not replace — manual security reviews and professional penetration testing. It may produce false positives and cannot detect all vulnerabilities.
