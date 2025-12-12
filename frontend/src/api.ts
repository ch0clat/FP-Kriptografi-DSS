const base = (import.meta.env.VITE_API_BASE || '').replace(/\/+$/, '')
export const apiBase = base

export function apiUrl(path: string): string {
  if (!path.startsWith('/')) throw new Error('apiUrl expects a leading slash')
  return base ? `${base}${path}` : path
}
