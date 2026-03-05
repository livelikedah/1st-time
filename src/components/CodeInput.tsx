import React, { useState, useRef } from 'react';
import { SAMPLE_VULNERABLE_CODE } from '../lib/scanner';

interface CodeInputProps {
  onScan: (code: string) => void;
  isScanning: boolean;
}

const CodeInput: React.FC<CodeInputProps> = ({ onScan, isScanning }) => {
  const [code, setCode] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleScan = () => {
    if (code.trim()) onScan(code);
  };

  const loadSample = () => {
    setCode(SAMPLE_VULNERABLE_CODE);
    setTimeout(() => textareaRef.current?.focus(), 50);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      handleScan();
    }
  };

  return (
    <div className="code-input-panel">
      <div className="panel-header">
        <span className="panel-title">
          <span className="terminal-prompt">$</span> paste_code_for_analysis
        </span>
        <div className="panel-actions">
          <button className="btn-ghost" onClick={loadSample} title="Load a sample vulnerable app">
            ⚡ Load Sample
          </button>
          <button className="btn-ghost" onClick={() => setCode('')} title="Clear editor">
            ✕ Clear
          </button>
        </div>
      </div>

      <div className="editor-wrapper">
        <div className="line-numbers" aria-hidden="true">
          {(code || ' ').split('\n').map((_, i) => (
            <div key={i} className="line-number">
              {i + 1}
            </div>
          ))}
        </div>
        <textarea
          ref={textareaRef}
          className="code-editor"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={`// Paste your JavaScript, TypeScript, or Node.js code here...\n// The AI security scanner will analyze it for vulnerabilities.\n// Press Ctrl+Enter to scan.\n\n// Tip: Click "Load Sample" to see a vulnerable app example.`}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
        />
      </div>

      <div className="scan-bar">
        <span className="char-count">
          {code.length.toLocaleString()} chars · {code.split('\n').length} lines
        </span>
        <button
          className="btn-scan"
          onClick={handleScan}
          disabled={isScanning || !code.trim()}
          aria-label="Scan code for vulnerabilities"
        >
          {isScanning ? (
            <>
              <span className="spinner" /> SCANNING...
            </>
          ) : (
            <>⚡ SCAN FOR VULNERABILITIES</>
          )}
        </button>
      </div>
    </div>
  );
};

export default CodeInput;
