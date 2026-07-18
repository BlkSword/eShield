/* 轻量状态总线：单一数据源 + 发布订阅，替代全局可变变量。 */

const state = new Map();
const listeners = new Map();

export const store = {
  get(key, fallback) {
    return state.has(key) ? state.get(key) : fallback;
  },
  set(key, value) {
    const old = state.get(key);
    state.set(key, value);
    if (old !== value) this.emit(key, value);
  },
  on(event, cb) {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event).add(cb);
    return () => listeners.get(event)?.delete(cb);
  },
  emit(event, data) {
    listeners.get(event)?.forEach(cb => {
      try { cb(data); } catch (e) { console.error(`store listener[${event}]`, e); }
    });
  },
};

/* 常用 key 约定：
 *   'stats'    — /api/stats 最新快照
 *   'config'   — /api/config 最新快照
 *   'theme'    — dark | light
 *   'sse'      — audit stream 连接状态 connected|connecting|error
 */
