/* API 封装：统一 Bearer/Cookie 认证、错误格式、401 跳转。 */

const TOKEN_KEY = 'eshield-token';

export function getToken() { return localStorage.getItem(TOKEN_KEY) || ''; }
export function setToken(t) { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); }

/**
 * 发起 API 请求。
 * @param {string} path 以 /api 开头的路径
 * @param {{method?: string, body?: any, query?: Record<string,any>}} opts
 * @returns {Promise<any>} 解析后的 JSON（无 JSON 时为文本）
 * @throws {Error} 携带后端 {error} 消息
 */
export async function api(path, opts = {}) {
  const url = new URL(path, location.origin);
  if (opts.query) {
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
    }
  }
  const headers = {};
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  let body;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  const resp = await fetch(url, { method: opts.method || 'GET', headers, body });
  if (resp.status === 401) {
    if (!location.pathname.startsWith('/login')) location.href = '/login';
    throw new Error('未授权，请重新登录');
  }
  const text = await resp.text();
  let data = text;
  try { data = JSON.parse(text); } catch { /* 纯文本响应 */ }
  if (!resp.ok) {
    const msg = (data && data.error) || `请求失败（${resp.status}）`;
    throw new Error(msg);
  }
  return data;
}

export const apiGet = (path, query) => api(path, { query });
export const apiPost = (path, body) => api(path, { method: 'POST', body });
export const apiPatch = (path, body) => api(path, { method: 'PATCH', body });
export const apiDelete = (path, body) => api(path, { method: 'DELETE', body });
