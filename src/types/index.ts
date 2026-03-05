export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  lineNumbers: number[];
  snippet: string;
  fix: string;
  references: string[];
  cwe?: string;
  owasp?: string;
}

export interface ScanResult {
  id: string;
  timestamp: Date;
  sourceCode: string;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
  improvements: Improvement[];
  score: number;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Improvement {
  id: string;
  title: string;
  description: string;
  category: string;
  priority: 'high' | 'medium' | 'low';
  example?: string;
  benefit: string;
}

export interface ScanRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  pattern: RegExp;
  fix: string;
  references: string[];
  cwe?: string;
  owasp?: string;
}
