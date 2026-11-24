# HubProxy 文档站

基于 [Astro Starlight](https://starlight.astro.build/)，默认中文，英文位于 `/en/`。

## 本地开发

```bash
cd docs
npm ci
npm run dev
```

## 构建

```bash
npm run build    # 输出到 dist/
npm run preview  # 本地预览构建结果
```

## 目录

```
src/content/docs/     # 中文文档
src/content/docs/en/  # 英文文档
src/assets/           # logo、hero 等资源
public/favicon.svg    # 浏览器标签页图标
src/styles/custom.css # 自定义样式
astro.config.mjs      # Starlight 配置
```

文档面向域名根路径部署。为独立文档域名构建时，将环境变量 `DOCS_SITE` 设为该站点的 HTTPS 地址，以生成指向本部署的规范链接和站点地图。GitHub Actions 从同名仓库变量读取此地址。工作流构建并保存 `docs/dist`，在仓库启用 GitHub Pages 时才执行发布步骤。

## 贡献

1. 修改 `src/content/docs/` 中文页面，并同步 `en/` 镜像
2. 侧边栏结构见 `astro.config.mjs`
3. 向主仓库提交 PR

