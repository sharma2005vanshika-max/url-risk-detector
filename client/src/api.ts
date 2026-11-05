// Automatically detect if running on GitHub Pages (static host) or on Render/Localhost
export const API_BASE = (typeof window !== 'undefined' && window.location.hostname.includes('github.io'))
  ? 'https://url-risk-detector.onrender.com'
  : '';

export function apiUrl(endpoint: string): string {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  return `${API_BASE}${cleanEndpoint}`;
}
