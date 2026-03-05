import React from 'react';
import type { ScanSummary } from '../types';

interface ScoreGaugeProps {
  score: number;
  summary: ScanSummary;
}

const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score, summary }) => {
  const color = score >= 80 ? '#00ff88' : score >= 50 ? '#ffaa00' : '#ff4444';
  const label = score >= 80 ? 'SECURE' : score >= 50 ? 'AT RISK' : 'VULNERABLE';

  const circumference = 2 * Math.PI * 54;
  const strokeDashoffset = circumference * (1 - score / 100);

  return (
    <div className="score-gauge">
      <div className="gauge-container">
        <svg width="140" height="140" viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="54" fill="none" stroke="#1a1f2e" strokeWidth="12" />
          <circle
            cx="70"
            cy="70"
            r="54"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            transform="rotate(-90 70 70)"
            style={{ transition: 'stroke-dashoffset 1s ease, stroke 0.5s ease' }}
          />
          <text x="70" y="65" textAnchor="middle" fill={color} fontSize="28" fontWeight="bold" fontFamily="monospace">
            {score}
          </text>
          <text x="70" y="83" textAnchor="middle" fill={color} fontSize="10" fontFamily="monospace">
            {label}
          </text>
        </svg>
      </div>

      <div className="summary-badges">
        {summary.critical > 0 && <span className="badge critical">CRITICAL: {summary.critical}</span>}
        {summary.high > 0 && <span className="badge high">HIGH: {summary.high}</span>}
        {summary.medium > 0 && <span className="badge medium">MEDIUM: {summary.medium}</span>}
        {summary.low > 0 && <span className="badge low">LOW: {summary.low}</span>}
        {summary.total === 0 && <span className="badge clean">✓ NO ISSUES FOUND</span>}
      </div>
    </div>
  );
};

export default ScoreGauge;
