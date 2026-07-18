/* Hash 路由器：页面注册、生命周期管理（轮询随页面卸载而停止）。 */
import { $ } from './format.js';

const pages = new Map();   // id → { title, sub?, mount(el, ctx) → unmountFn? }
let currentId = null;
let currentUnmount = null;

export function registerPage(id, def) {
  pages.set(id, def);
}

export function currentPage() { return currentId; }

function pageFromHash() {
  const h = location.hash.replace(/^#\/?/, '').split('?')[0];
  return pages.has(h) ? h : 'overview';
}

export function navigate(id) {
  location.hash = '#/' + id;
}

function render() {
  const id = pageFromHash();
  if (id === currentId) return;
  if (typeof currentUnmount === 'function') {
    try { currentUnmount(); } catch (e) { console.error('unmount', e); }
  }
  currentUnmount = null;
  currentId = id;
  const def = pages.get(id);
  document.querySelectorAll('[data-nav]').forEach(b =>
    b.classList.toggle('active', b.dataset.nav === id));
  $('#pageTitle').textContent = def.title;
  $('#pageSub').textContent = typeof def.sub === 'function' ? def.sub() : (def.sub || '');
  const el = $('#page');
  el.innerHTML = '';
  const result = def.mount(el, {});
  if (typeof result === 'function') currentUnmount = result;
  window.dispatchEvent(new CustomEvent('page:changed', { detail: id }));
}

export function startRouter() {
  window.addEventListener('hashchange', render);
  render();
}
