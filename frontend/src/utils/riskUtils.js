/**
 * Maps a numeric CVSS score or a raw severity string to a standardized 
 * SwitchGuard risk level (Critical, High, Medium, Low, Informational).
 */
export const getRiskLevel = (indicator) => {
  if (!indicator) return 'Informational';

  // Handle numeric scores
  if (typeof indicator === 'number') {
    if (indicator >= 9.0) return 'Critical';
    if (indicator >= 7.0) return 'High';
    if (indicator >= 4.0) return 'Medium';
    if (indicator >= 0.1) return 'Low';
    return 'Informational';
  }

  // Handle strings (lowercase normalization)
  const risk = String(indicator).toLowerCase();
  
  if (risk.includes('critical')) return 'Critical';
  if (risk.includes('high'))     return 'High';
  if (risk.includes('medium'))   return 'Medium';
  if (risk.includes('low'))      return 'Low';
  
  return 'Informational';
};

/**
 * Standard colors for risk badges.
 */
export const RISK_COLORS = {
  Critical: '#f43f5e',
  High: '#ef4444',
  Medium: '#f59e0b',
  Low: '#10b981',
  Informational: '#6b7280',
};
