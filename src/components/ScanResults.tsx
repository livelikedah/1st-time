import React, { useState } from 'react';
import type { Vulnerability, Severity } from '../types';

interface ScanResultsProps {
  vulnerabilities: Vulnerability[];
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '💀',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
  info: 'ℹ️',
};

const ScanResults: React.FC<ScanResultsProps> = ({ vulnerabilities }) => {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<Severity | 'all'>('all');

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => setExpanded(new Set(vulnerabilities.map((v) => v.id)));
  const collapseAll = () => setExpanded(new Set());

  const sorted = [...vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  const filtered = filter === 'all' ? sorted : sorted.filter((v) => v.severity === filter);

  if (vulnerabilities.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-icon">✅</div>
        <h3>No Vulnerabilities Found</h3>
        <p>Great news! The scanner found no known vulnerability patterns in your code. Remember, this scanner uses static analysis and may not catch all issues — always combine with manual review and penetration testing.</p>
      </div>
    );
  }

  return (
    <div className="results-panel">
      <div className="results-toolbar">
        <div className="filter-tabs">
          <button
            className={`filter-tab ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            All ({vulnerabilities.length})
          </button>
          {SEVERITY_ORDER.map((sev) => {
            const count = vulnerabilities.filter((v) => v.severity === sev).length;
            if (count === 0) return null;
            return (
              <button
                key={sev}
                className={`filter-tab ${filter === sev ? 'active' : ''} sev-${sev}`}
                onClick={() => setFilter(sev)}
              >
                {SEVERITY_ICONS[sev]} {sev.toUpperCase()} ({count})
              </button>
            );
          })}
        </div>
        <div className="toolbar-actions">
          <button className="btn-ghost" onClick={expandAll}>Expand All</button>
          <button className="btn-ghost" onClick={collapseAll}>Collapse All</button>
        </div>
      </div>

      <div className="vuln-list">
        {filtered.map((vuln) => (
          <div key={vuln.id} className={`vuln-card sev-border-${vuln.severity}`}>
            <button
              className="vuln-header"
              onClick={() => toggle(vuln.id)}
              aria-expanded={expanded.has(vuln.id)}
            >
              <div className="vuln-meta">
                <span className={`severity-tag sev-${vuln.severity}`}>
                  {SEVERITY_ICONS[vuln.severity]} {vuln.severity.toUpperCase()}
                </span>
                <span className="category-tag">{vuln.category}</span>
                {vuln.cwe && <span className="cwe-tag">{vuln.cwe}</span>}
                {vuln.owasp && <span className="owasp-tag">{vuln.owasp}</span>}
              </div>
              <div className="vuln-title-row">
                <span className="vuln-name">{vuln.name}</span>
                <span className="vuln-line">Line {vuln.lineNumbers.join(', ')}</span>
              </div>
              <span className={`expand-icon ${expanded.has(vuln.id) ? 'expanded' : ''}`}>▼</span>
            </button>

            {expanded.has(vuln.id) && (
              <div className="vuln-body">
                <section className="vuln-section">
                  <h4>📖 Description</h4>
                  <p>{vuln.description}</p>
                </section>

                <section className="vuln-section">
                  <h4>🔍 Detected Code</h4>
                  <pre className="code-snippet">
                    <code>...{vuln.snippet}...</code>
                  </pre>
                </section>

                <section className="vuln-section fix-section">
                  <h4>🛠️ How to Fix</h4>
                  <p>{vuln.fix}</p>
                </section>

                {vuln.references.length > 0 && (
                  <section className="vuln-section">
                    <h4>📚 References</h4>
                    <ul className="ref-list">
                      {vuln.references.map((ref) => (
                        <li key={ref}>
                          <a href={ref} target="_blank" rel="noopener noreferrer">
                            {ref}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </section>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default ScanResults;
