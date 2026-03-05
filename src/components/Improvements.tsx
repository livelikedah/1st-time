import React, { useState } from 'react';
import type { Improvement } from '../types';

interface ImprovementsProps {
  improvements: Improvement[];
}

const PRIORITY_ICONS: Record<string, string> = {
  high: '🔥',
  medium: '⚡',
  low: '💡',
};

const Improvements: React.FC<ImprovementsProps> = ({ improvements }) => {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filtered = filter === 'all' ? improvements : improvements.filter((i) => i.priority === filter);
  const priorityOrder = { high: 0, medium: 1, low: 2 };
  const sorted = [...filtered].sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  return (
    <div className="improvements-panel">
      <div className="improvements-intro">
        <p>
          These are <strong>best-practice improvements</strong> to harden your application beyond fixing the detected
          vulnerabilities. Apply them proactively to build defense-in-depth.
        </p>
      </div>

      <div className="results-toolbar">
        <div className="filter-tabs">
          {(['all', 'high', 'medium', 'low'] as const).map((p) => (
            <button
              key={p}
              className={`filter-tab ${filter === p ? 'active' : ''}`}
              onClick={() => setFilter(p)}
            >
              {p !== 'all' && PRIORITY_ICONS[p]} {p.toUpperCase()}
              {p !== 'all' && ` (${improvements.filter((i) => i.priority === p).length})`}
            </button>
          ))}
        </div>
      </div>

      <div className="improvement-list">
        {sorted.map((imp) => (
          <div key={imp.id} className={`improvement-card priority-${imp.priority}`}>
            <button
              className="improvement-header"
              onClick={() => toggle(imp.id)}
              aria-expanded={expanded.has(imp.id)}
            >
              <div className="imp-meta">
                <span className={`priority-tag priority-${imp.priority}`}>
                  {PRIORITY_ICONS[imp.priority]} {imp.priority.toUpperCase()}
                </span>
                <span className="category-tag">{imp.category}</span>
              </div>
              <div className="imp-title-row">
                <span className="imp-title">{imp.title}</span>
              </div>
              <span className={`expand-icon ${expanded.has(imp.id) ? 'expanded' : ''}`}>▼</span>
            </button>

            {expanded.has(imp.id) && (
              <div className="vuln-body">
                <section className="vuln-section">
                  <h4>📖 Description</h4>
                  <p>{imp.description}</p>
                </section>

                <section className="vuln-section fix-section">
                  <h4>🎯 Business Benefit</h4>
                  <p>{imp.benefit}</p>
                </section>

                {imp.example && (
                  <section className="vuln-section">
                    <h4>💻 Example Implementation</h4>
                    <pre className="code-snippet">
                      <code>{imp.example}</code>
                    </pre>
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

export default Improvements;
