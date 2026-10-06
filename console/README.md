# eShield Console

eShield 控制台前端工程。Vue 3 + TypeScript + Vite，构建产物是**单文件 HTML**，
由 `eshield/src/web.rs` 通过 `include_bytes!("../web/app.html")` 嵌入二进制。

## 技术选型

| 层 | 选择 | 说明 |
|---|---|---|
| 框架 | Vue 3.5（`<script setup>` + TypeScript） | 组件化，组合式 API |
| 路由 | vue-router 4（hash 模式） | 单文件产物无需服务端 fallback |
| 图表 | ECharts 5 | 流量趋势、拦截原因分布 |
| 构建 | Vite 6 + vite-plugin-singlefile | 输出单一 `dist/index.html` |
| 样式 | 原生 CSS + design tokens | 跟随 `prefers-color-scheme`，支持手动切换 |
| 测试 | vue-tsc 类型检查 + Playwright 预览截图（可选） | `scripts/shot.mjs` |

不引入重型 UI 组件库，表格、抽屉、弹窗、命令面板、开关等均为自研组件，
以便统一高密度运维控制台的视觉语言。

## 目录结构

```
console/
├─ src/
│  ├─ components/       # 通用组件：EChart、KPI、面板、抽屉、弹窗、命令面板…
│  ├─ views/            # 页面：总览、攻击、包日志、审计、模块、访问控制、L7…
│  ├─ api/              # client.ts（live/mock 自适应）+ mock.ts + types.ts
│  ├─ stores/           # app（统计/主题/刷新）、ui（抽屉/弹窗）
│  ├─ router/           # 路由与左侧导航分组
│  ├─ utils/            # 数字/时间格式化
│  └─ styles/app.css    # design tokens + 全部组件样式
├─ scripts/shot.mjs     # 用本机 Chrome/Edge 渲染 design/console-v2/*.png
├─ vite.config.ts
└─ package.json
```

## 开发与构建

```bash
cd console
npm install
npm run dev        # 本地开发，默认 mock 数据
npm run build      # vue-tsc 类型检查 + 产物 dist/index.html
```

构建后同步到 Rust 侧：

```bash
cp console/dist/index.html eshield/web/app.html
```

## 数据模式

`src/api/client.ts` 自动判断：

- 通过 eShield 服务访问（http/https）：调用真实 `/api/*`，登录态用 `eshield-token`
  Cookie 或 `Authorization: Bearer`；
- 直接打开 `dist/index.html` / `design/console-v2/preview.html`（file://）或
  接口不可达：回退到 `mock.ts` 的样例数据，页面顶部显示「演示数据」；
- 可用 `?mock=1` / `?live=1` 强制模式。

## 页面

总览、攻击事件、包日志、审计日志、防护模块、访问控制（黑名单/白名单/端口 ACL）、
L7 指纹、防护项目、GeoIP 与情报、规则与 Hub、系统设置、登录。

## 设计语言

- 浅色优先，跟随系统深浅色；手动切换记录在 `localStorage`；
- 左侧 232px 文本导航，顶部 60px 全局栏（搜索、实时状态、危险等级、主题）；
- 8px 间距栅格，10px 卡片圆角，弱阴影，克制状态色；
- 数字与 IP/端口使用等宽字体，表格行高 32–36px，适配高密度运维场景；
- 无障碍：开关使用 `aria-pressed`，命令面板支持方向键/回车/Esc。

## 与旧版控制台的关系

新版 `app.html` 由 `web.rs` 在 `/` 与 `/login` 提供；旧版 `eshield/web/index.html`、
`css/`、`js/` 仍保留在 `include_bytes!` 静态资源表中，但不再作为入口。后续可移除。

## 示例界面

仓库内 `console/preview/` 保存了用本机 Chrome 渲染的页面截图：

| 页面 | 预览 |
|---|---|
| 总览 | `console/preview/overview.png` |
| 攻击事件 | `console/preview/attacks.png` |
| 防护模块 | `console/preview/modules.png` |
| 访问控制 | `console/preview/access.png` |
| 防护项目 | `console/preview/projects.png` |
| L7 指纹 | `console/preview/l7.png` |

也可以直接双击打开 `eshield/web/app.html`：未连接节点时自动进入演示数据模式，
可完整浏览总览、攻击、模块、访问控制、项目、GeoIP、Hub、设置与登录页。

重新生成截图（需要本机 Chrome/Edge）：

```bash
cd console
npm i -D playwright-core
node scripts/shot.mjs "C:/Program Files/Google/Chrome/Application/chrome.exe"
```

## 前后端接线自检

`scripts/mockapi.py` 按 `eshield/src/web.rs` 的真实返回结构（包括 `{series}`、`{modules}`、
`{events}`、`{entries}` 等 envelope）提供本地 mock API；`scripts/wiring.mjs` 用无头 Chrome
驱动构建产物逐页断言「是否拿到 live 数据、字段是否正确、页面是否报错」。

```bash
# 终端 1：启动 mock API，同时托管 app.html
python console/scripts/mockapi.py 8898

# 终端 2：运行接线断言（11 个页面 + IP 详情抽屉）
cd console
node scripts/wiring.mjs "C:/Program Files/Google/Chrome/Application/chrome.exe" http://127.0.0.1:8898
```

覆盖页面：总览、攻击事件、包日志、审计日志、防护模块、访问控制（黑名单/白名单/端口 ACL）、
L7 指纹、防护项目、GeoIP 与情报、规则与 Hub、系统设置、IP 详情抽屉。
后端字段或 envelope 变化时，这个脚本会直接失败，作为契约回归。

## 构建产物与二进制

`eshield/src/web.rs` 通过 `include_str!("../web/app.html")` 嵌入 SPA。旧版
`eshield/web/{index.html,css,js}` 已不再被引用，保留仅为回退参考；后续可整体删除。
