import React, { useState, useCallback } from 'react';
import CodeInput from './components/CodeInput';
import ScanResults from './components/ScanResults';
import Improvements from './components/Improvements';
import ScoreGauge from './components/ScoreGauge';
import { scanCode } from './lib/scanner';
import type { ScanResult } from './types';
import './App.css';

type Tab = 'input' | 'results' | 'improvements';

const App: React.FC = () => {
  const [tab, setTab] = useState<Tab>('input');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const handleScan = useCallback((code: string) => {
    setIsScanning(true);
    // Simulate async scanning with a small delay for UX
    setTimeout(() => {
      const scanResult = scanCode(code);
      setResult(scanResult);
      setIsScanning(false);
      setTab('results');
    }, 600);
  }, []);

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="app-header">
        <div className="header-inner">
          <div className="logo">
            <span className="logo-icon">🔐</span>
            <div className="logo-text">
              <span className="logo-name">AI Security Analyzer</span>
              <span className="logo-tagline">Autonomous Vulnerability Scanner &amp; Code Auditor</span>
            </div>
          </div>
          <div className="header-badges">
            <span className="tech-badge">React</span>
            <span className="tech-badge">TypeScript</span>
            <span className="tech-badge">OWASP Top 10</span>
          </div>
        </div>
      </header>

      {/* ── Scan score bar ── */}
      {result && (
        <div className="score-bar">
          <ScoreGauge score={result.score} summary={result.summary} />
          <div className="scan-meta">
            <div className="scan-meta-row">
              <span className="meta-label">Scanned:</span>
              <span className="meta-value">{result.timestamp.toLocaleTimeString()}</span>
            </div>
            <div className="scan-meta-row">
              <span className="meta-label">Lines:</span>
              <span className="meta-value">{result.sourceCode.split('\n').length}</span>
            </div>
            <div className="scan-meta-row">
              <span className="meta-label">Issues found:</span>
              <span className={`meta-value ${result.summary.total > 0 ? 'text-danger' : 'text-success'}`}>
                {result.summary.total}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ── Navigation Tabs ── */}
      <nav className="tab-nav" role="tablist">
        <button
          role="tab"
          aria-selected={tab === 'input'}
          className={`tab ${tab === 'input' ? 'active' : ''}`}
          onClick={() => setTab('input')}
        >
          <span className="tab-icon">📋</span> Code Input
        </button>
        <button
          role="tab"
          aria-selected={tab === 'results'}
          className={`tab ${tab === 'results' ? 'active' : ''}`}
          onClick={() => setTab('results')}
          disabled={!result}
        >
          <span className="tab-icon">🔍</span> Vulnerabilities
          {result && result.summary.total > 0 && (
            <span className="tab-badge">{result.summary.total}</span>
          )}
        </button>
        <button
          role="tab"
          aria-selected={tab === 'improvements'}
          className={`tab ${tab === 'improvements' ? 'active' : ''}`}
          onClick={() => setTab('improvements')}
          disabled={!result}
        >
          <span className="tab-icon">💡</span> Improvements
          {result && <span className="tab-badge">{result.improvements.length}</span>}
        </button>
      </nav>

      {/* ── Tab Panels ── */}
      <main className="main-content">
        {tab === 'input' && (
          <CodeInput onScan={handleScan} isScanning={isScanning} />
        )}
        {tab === 'results' && result && (
          <ScanResults vulnerabilities={result.vulnerabilities} />
        )}
        {tab === 'improvements' && result && (
          <Improvements improvements={result.improvements} />
        )}
      </main>

      {/* ── Footer ── */}
      <footer className="app-footer">
        <p>
          🔐 AI Security Analyzer · Static analysis only · Always combine with manual pen-testing ·{' '}
          <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer">
            OWASP Top 10
          </a>
        </p>
      </footer>
    </div>
  );
};

export default App;
