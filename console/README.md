# eShield Console

eShield 控制台前端工程。Vue 3 + TypeScript + Vite，构建产物是**单文件 HTML**，
由 `eshield/src/web.rs` 通过 `include_str!("../web/app.html")` 嵌入二进制。

## 技术选型

| 层 | 选择 | 说明 |
|---|---|---|
| 框架 | Vue 3.5（`<script setup>` + TypeScript） | 组件化，组合式 API |
| 路由 | vue-router 4（hash 模式） | 单文件产物无需服务端 fallback |
| 图表 | **自研 SVG 组件**（`LineChart` / `BarList` / `Sparkline`） | 无第三方图表库，体积与首屏均更优 |
| 构建 | Vite 6 + vite-plugin-singlefile | 输出单一 `dist/index.html` |
| 样式 | 原生 CSS + design tokens | 浅/深两套 token，跟随系统或手动切换 |
| 测试 | `vue-tsc` 类型检查 + `scripts/wiring.mjs` 端到端接线检查 | 见下 |

不引入 UI 组件库：表格、抽屉、弹窗、命令面板、开关、分段控件均为自研手写，
以保证统一的高密度运维视觉语言。

## 设计系统 v2（高效商业控制台）

原型与页面截图见 `design-preview/`（`prototype.html` + `v2-*.png`）。

五条硬规则（实现于 `src/styles/app.css` 顶部 tokens 与各组件）：

1. **结构用线，不用影**：面板 / 表格 / KPI 一律 1px 描边 + 2–3px 圆角，无卡片阴影与渐变。
2. **颜色只表达状态**：`accent`=可交互，`danger`=危险，`warn`=警告，`ok`=正常；不做装饰性色块。
3. **数字优先**：等宽数字、右对齐、千分位；IP / 端口 / 时间统一 `--font-mono`。
4. **密度优先**：行高 34px、面板头 38px、导航 30px、顶栏 44px。
5. **层级克制**：页面标题 17 / 正文 12.5 / 说明 11 / 表头 10.5，仅 4 级。

历史版本（彩色 KPI 卡片 + ECharts 饼图 + Tag 胶囊）已删除；单文件产物从
**1.26MB 降到 239KB**（gzip 80KB），首屏解析与传输成本显著下降。

## 目录结构

```
console/
├─ src/
│  ├─ components/       # LineChart / BarList / Sparkline / KpiCard / PanelCard
│  │                    # SideNav / TopBar / SlideDrawer / ModalDialog / CommandPalette …
│  ├─ views/            # 12 个页面：总览、攻击、包日志、审计、模块、访问控制、L7…
│  ├─ api/              # client.ts（live/mock 自适应）+ mock.ts + types.ts
│  ├─ stores/           # app（统计/主题/刷新）、ui（抽屉/弹窗）
│  ├─ router/           # 路由与左侧导航分组
│  ├─ utils/            # 数字/时间格式化
│  └─ styles/app.css    # design tokens + 壳层与全部组件样式
├─ scripts/mockapi.py   # 本地 mock API + SPA 宿主（接线测试用）
├─ scripts/wiring.mjs   # Playwright 驱动，逐页断言「渲染的是真实 API 数据」
├─ design-preview/      # 设计原型与页面截图（非构建产物）
├─ vite.config.ts
└─ package.json
```

## 开发与构建

```bash
cd console
npm install
npm run dev        # 本地开发（file 协议或接口不可达时自动使用 mock 数据）
npm run build      # vue-tsc 类型检查 + 产物 dist/index.html
```

构建后同步到 Rust 侧（页面会内嵌进 `eshield` 二进制）：

```bash
cp console/dist/index.html eshield/web/app.html
```

## 数据模式

`src/api/client.ts` 自动判断：

- 通过 eShield 服务访问（http/https）：调用真实 `/api/*`，登录态用 `eshield-token`
  Cookie 或 `Authorization: Bearer`；
- 直接打开 `dist/index.html`（file://）或接口不可达：回退到 `mock.ts` 的样例数据，
  顶栏显示「演示数据」；
- 可用 `?mock=1` / `?live=1` 强制模式；`?theme=dark|light` 可覆盖主题（演示/截图用）。

## 验证

```bash
# 1) 类型检查 + 构建
npm run build

# 2) 接线检查：mock API 与单文件产物一起跑，逐页断言关键字段来自 API
python scripts/mockapi.py 8898 &
node scripts/wiring.mjs            # 11 个页面 + 访问控制三个 Tab + IP 详情抽屉
```

`wiring.mjs` 覆盖：overview / attacks / packets / audit / modules / access / l7 /
projects / geoip / rules / settings，以及白名单、端口 ACL 两个 Tab、IP 详情抽屉，
并断言页面无 `pageerror`。

## 截图

```bash
# 需要本机 Chrome/Edge；file:// 打开时自动使用 mock 数据
"C:\Program Files\Google\Chrome\Application\chrome.exe" \
  --headless=new --disable-gpu --window-size=1600,1050 --virtual-time-budget=4000 \
  --screenshot=design-preview/v2-overview.png \
  "file:///<abs>/console/dist/index.html#/overview"
```
