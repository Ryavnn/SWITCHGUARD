/**
 * Standardizes risk strings and severity levels.
 */
export const formatRiskLevel = (risk = '') => {
  if (!risk) return 'informational';
  return risk.toLowerCase();
};

/**
 * Formats ISO dates to local strings.
 */
export const formatDate = (dateStr) => {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleString();
};

/**
 * Common color mapping for vulnerabilities.
 */
export const VULN_COLORS = {
  critical: '#f43f5e',
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#10b981',
  informational: '#6b7280',
};
