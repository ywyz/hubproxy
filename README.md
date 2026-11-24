# HubProxy

本仓库是 [sky22333/hubproxy](https://github.com/sky22333/hubproxy) 的分支。原版提供 Docker Registry 拉取、离线镜像打包、镜像搜索，以及 GitHub 和 Hugging Face 文件加速。

## 与原版的区别

以下对比以分叉时的[上游提交 `77ece22`](https://github.com/sky22333/hubproxy/tree/77ece220eed26a2be12b03cf5f46173156ac55fb) 为准。

| 场景 | 原版 | 本分支 |
| --- | --- | --- |
| HTTPS 文件直链 | 按预设的 GitHub、Hugging Face 等地址规则转发 | 可按主机和路径放行其他 HTTPS 文件，使用独立的 `directLinkWhiteList` 和 `directLinkBlackList`。经过 HTTPS 出站代理时，分别校验代理和下载目标的证书。 |
| Linux 软件包源 | 无专用软件包镜像入口 | `/mirrors/<上游主机>/<路径>` 原样传输仓库元数据、软件包和签名。随附配置放行 Ubuntu、Debian、Omarchy stable、Arch、Alpine 和 Rocky Linux 的指定目录。 |
| 大文件下载 | GitHub 文件受 `[server].fileSize` 限制 | 该值成为匿名下载门槛，默认和最高均为 2 GiB。配置本地下载账户后，浏览器登录或 IDM 通过 HTTPS 认证即可下载更大的文件。分段下载按完整文件大小判断。 |

从原版迁移时，保留自己的 `config.toml`，按需从 [src/config.toml](src/config.toml) 合并软件源规则。旧配置缺少直链白名单时，通用直链和软件包镜像会返回 403。登录不会放宽目标访问名单。[完整功能对比](docs/src/content/docs/guides/capabilities.mdx)

## 特性

- 🐳 **Docker 镜像加速** — 兼容 Registry API v2，支持 Docker Hub、GHCR、Quay、GCR、registry.k8s.io；流式传输，Manifest / Token 缓存
- 📦 **离线镜像包** — 无需本地 Docker，可将单个镜像或多个镜像打包为 tar。匿名请求先暂存归档并检查大小，登录后可边打包边下载。
- 📁 **文件下载加速** — GitHub Release、Raw、Git Clone、`api.github.com` 与显式白名单授权的任意 HTTPS 直链；`.sh` / `.ps1` 脚本内 URL 自动改写
- 🤖 **Hugging Face 加速** — 模型文件与 LFS 大文件下载
- 🔍 **镜像搜索** — Web 界面与 API 搜索 Docker Hub 镜像、浏览标签
- 🛡️ **智能限流** — 按真实客户端 IP 令牌桶限流（IPv6 按 `/64`）；可配置周期与配额
- 🚫 **资源访问控制** — IP 黑白名单（限流豁免 / 封禁）+ 镜像 / GitHub 仓库名单 + 独立的 HTTPS 直链名单，支持通配符
- 🌐 **出站代理** — 文件下载支持 HTTP、HTTPS 和 SOCKS5 代理，可用 `NO_PROXY` 为指定主机选择直连。
- 🖥️ **Web 界面** — 内置 Vue SPA，镜像搜索、离线包下载、标签浏览
- ⚡ **轻量高效** — Go 单二进制，支持 `deb` / `rpm` / `apk` 与 Docker 多架构镜像
- 🔧 **统一配置** — `config.toml` + 环境变量覆盖，开箱即用
- 🚀 **多服务统一加速** — 单个程序覆盖 Docker、GitHub、Hugging Face，简化部署
- ☁️ **完全自托管** — 不依赖第三方免费 CDN 代理，数据与带宽自主可控

## 快速开始

### Docker 部署（推荐）

安装 Git 和带 Compose 插件的 Docker，然后从本仓库构建。

```bash
git clone --branch main https://github.com/ywyz/hubproxy.git
cd hubproxy
docker compose up -d --build
curl -fsS --retry 10 --retry-connrefused http://127.0.0.1:5000/ready
```

就绪响应包含 `"ready":true`。根目录的 Compose 将服务发布到宿主机 5000 端口，可在本机浏览器打开 `http://127.0.0.1:5000/`。原版系统安装脚本下载的是上游发行包。[上游系统包安装说明](docs/src/content/docs/getting-started/install.mdx)

### 生产部署与升级

从已审阅的提交构建带版本号的镜像，将镜像归档和 SHA-256 校验文件传到服务器，再用生产 Compose 模板启动。模板发布到宿主机回环地址 `127.0.0.1:15001`，供 Caddy 或 Nginx 提供公网 HTTPS。升级后核对 `/ready` 返回的版本并测试下载；回滚时切回保留的上一镜像。分步命令见 [Docker 部署指南](docs/src/content/docs/deployment/docker.mdx)，模板见 [deploy/compose.yaml](deploy/compose.yaml)。

### 快速上手

将 `yourdomain.com` 换成你的 `HubProxy` 地址
```bash
# Docker 镜像加速
docker pull yourdomain.com/nginx

# GitHub Release 加速
wget "https://yourdomain.com/https://github.com/owner/repo/releases/download/v1.0.0/app.tar.gz"

# Git clone 加速
git clone https://yourdomain.com/https://github.com/ywyz/hubproxy.git
```

### 大文件与软件包镜像

要开放超过匿名门槛的文件，请设置 `HUBPROXY_DOWNLOAD_USERNAME` 和 `HUBPROXY_DOWNLOAD_PASSWORD`，重新运行对应的 Compose 启动命令使环境变量生效。浏览器在 `/login` 登录，IDM 可在“选项 → 站点登录”中保存 HubProxy 的 HTTPS 地址及账号。[大文件与 IDM 指南](docs/src/content/docs/guides/github-proxy.mdx)

使用 `/mirrors/<上游主机>/<原路径>` 可代理 Ubuntu、Debian、Omarchy stable、Arch Linux、Alpine 和 Rocky Linux 的预置软件源。例如，Ubuntu 主仓库可使用 `https://你的域名/mirrors/archive.ubuntu.com/ubuntu`。自定义挂载的 `config.toml` 会覆盖镜像配置，已有部署可将所需目录合并到直链白名单。[内置仓库清单和包管理器配置](docs/src/content/docs/guides/package-mirrors.mdx)

## 详细文档

- [中文快速开始](docs/src/content/docs/getting-started/quick-start.mdx) · [配置参考](docs/src/content/docs/configuration/reference.mdx) · [反向代理](docs/src/content/docs/deployment/reverse-proxy.mdx)
- [English quick start](docs/src/content/docs/en/getting-started/quick-start.mdx) · [Fork differences](docs/src/content/docs/en/guides/capabilities.mdx) · [Production deployment](docs/src/content/docs/en/deployment/docker.mdx)


## 界面预览

![demo](.github/demo/demo.png)

## 免责声明

- 本程序仅供学习交流使用，请勿用于非法用途
- 使用本程序需遵守当地法律法规
- 作者不对使用者的任何行为承担责任

---

**如果这个项目对你有帮助，请给个 Star ⭐**
