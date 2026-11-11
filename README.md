# Domain Manager
<img width="1920" height="920" alt="image" src="https://github.com/user-attachments/assets/d5b705cf-b336-4bbb-b6c9-c5c75bd61817" />

域名与 HTTPS SSL 证书监控管理系统。使用 Go + Vue 3 开发，前端静态资源通过 `go:embed` 嵌入后端，最终交付为**单个 Linux 二进制文件**，运行时不依赖 Node.js、MySQL、Redis、Nginx 或 Docker。

- 后端：Go 1.24+、Gin、GORM、SQLite（纯 Go 驱动，可静态交叉编译）
- 前端：Vue 3、TypeScript、Vite、Element Plus、Axios、ECharts
- 定时任务：robfig/cron
- ACME：go-acme/lego v4，Let's Encrypt HTTP-01 / DNS-01
- 通知：Telegram、Lark、飞书、钉钉
- 默认监听：`http://127.0.0.1:10120`
- 数据库：`./data/domain-manager.db`
- 日志：`./logs/domain-manager.log`

---

## 功能总览

### 域名监控

- 添加域名、批量导入、CSV / TXT 导入、单条检测、全部检测
- **优先使用 RDAP**，RDAP 无结果时自动回退 WHOIS
- 自动识别注册商、注册日期、到期日期，计算剩余天数
- 域名状态：正常、即将到期、已过期、查询失败、待检测
- 查询失败会保存错误原因，**不会把查询失败判定为已过期**
- 支持手动锁定到期时间，适用于注册局未开放 RDAP/WHOIS 信息的域名
- 可对单个域名暂停监控

### SSL 证书监控

- 自动进行 TLS 握手、获取叶子证书和证书链
- 获取颁发机构、生效时间、到期时间、序列号、SAN 列表
- 校验系统信任链、证书域名匹配、是否过期/即将到期
- HTTPS 可访问性检查（区分不可访问、HTTP 5xx、证书异常）
- 支持自定义端口、自定义 SNI
- 支持“跳过证书校验”诊断模式（默认关闭，不会作为默认安全策略）
- 状态：正常、即将到期、已过期、HTTPS 不可访问、证书异常、检测失败、待检测

### Let's Encrypt / ACME

- 证书申请、手动续期、到期前自动续期
- HTTP-01：内置 Standalone 服务器或 Webroot 文件模式
- DNS-01：Cloudflare、DNSPod / 腾讯云、阿里云 DNS
- 多域名 SAN、泛域名（强制 DNS-01）
- Staging / Production 环境切换，**默认 Staging**
- 独立订单、实时申请日志、失败自动重试（指数退避，遵守 CA 限流）
- PEM 下载：`cert.pem`、`chain.pem`、`fullchain.pem`、`privkey.pem`
- 签发后自动续期、文件部署、部署脚本
- 私钥 0600 权限保存，页面和普通 API 不展示私钥内容

### 告警通知

- Telegram Bot、Lark 自定义机器人、飞书自定义机器人、钉钉自定义机器人
- 多个通知渠道，可独立启用/禁用
- 事件与渠道绑定：域名到期、SSL 到期、申请成功、续期成功、申请失败、系统异常、恢复通知
- 测试消息、发送日志、失败重试
- 告警去重与恢复通知
- 默认告警阈值可在后台修改

### 安全管理

- 管理员登录、会话管理与首次登录强制修改密码
- TOTP 二次认证，支持任意兼容 TOTP 的身份验证器
- 启用时在网页直接生成并显示 TOTP 二维码，同时保留手动密钥与 otpauth 链接
- 一次性恢复码、恢复码重新生成、二次认证关闭
- TOTP 密钥 AES-GCM 加密存储，验证码重放防护

### 仪表盘

- 域名/SSL 总数、正常、即将到期、已过期、HTTPS 异常、今日检测、今日告警
- 域名与证书状态分布、最近 30 天检测趋势
- 未来 30 天到期域名与证书列表、最近告警记录

---

## 快速开始

### 直接运行

```bash
chmod +x domain-manager-linux-amd64
./domain-manager-linux-amd64
```

首次启动会自动：

1. 创建 `configs/config.yaml`（如果不存在）
2. 创建 `data/`、`logs/`、证书与 ACME 目录
3. 初始化 SQLite 数据库并执行迁移
4. 写入默认系统配置、通知规则与定时任务
5. 创建管理员账号并生成随机密码
6. 注册并启动定时任务
7. 启动 HTTP 服务

首次运行的终端会输出类似内容：

```text
============================================================
 Domain Manager 首次初始化完成
 管理后台: http://127.0.0.1:10120
 管理员账号: admin
 初始密码文件: ./data/initial-admin-password（权限 0600）
 请立即登录并修改密码！
 所有域名与证书数据保存在: ./data/domain-manager.db
============================================================
```

默认只监听 `127.0.0.1:10120`。本机浏览器访问 `http://127.0.0.1:10120`；远程访问请先配置 HTTPS 反向代理（见下文），不要把明文 HTTP 直接暴露到公网。首次登录后必须修改密码，否则除 `/auth/me`、`/auth/password`、`/auth/logout` 外的 API 均返回 403。

### 修改监听端口

三种方式任选其一：

```bash
./domain-manager -port 8080
```

```bash
DM_PORT=8080 ./domain-manager
```

或在 `configs/config.yaml` 中修改：

```yaml
server:
  host: 127.0.0.1
  port: 8080
```

---

## 配置

### 配置文件

默认读取 `configs/config.yaml`，不存在时会自动生成。示例见 `configs/config.example.yaml`。

```yaml
server:
  host: 127.0.0.1
  port: 10120
  mode: release
  cookie_secure: false
  trusted_proxies: ["127.0.0.1"]
  read_timeout_seconds: 30
  write_timeout_seconds: 60
  max_upload_mb: 100

data_dir: ./data
log_dir: ./logs
database_path: ./data/domain-manager.db
log_level: info
```

### 环境变量

| 变量 | 说明 |
|---|---|
| `DM_ADDR` / `DM_PORT` | 监听地址 / 端口 |
| `DM_DATA_DIR` | 数据目录 |
| `DM_LOG_DIR` | 日志目录 |
| `DM_DB_PATH` | SQLite 文件路径 |
| `DM_GIN_MODE` | `release` / `debug` / `test` |
| `DM_COOKIE_SECURE` | 是否只通过 HTTPS 发送会话 Cookie |
| `DM_LOG_LEVEL` | `debug` / `info` / `warn` / `error` |
| `DM_ADMIN_USER` | 首次初始化的管理员用户名，默认 `admin` |
| `DM_ADMIN_PASSWORD` | 首次初始化的管理员密码；不设置则随机生成 |
| `DM_CONFIG` | 配置文件路径（也可用 `-config` 参数） |

命令行参数：`-config`、`-port`、`-data-dir`、`-version`。

### 反向代理与 HTTPS

程序默认直接监听 HTTP。生产环境建议在前面放置 HTTPS 反向代理（Nginx / Caddy / Traefik），并设置：

```yaml
server:
  cookie_secure: true
  trusted_proxies: ["127.0.0.1"]
```

Nginx 示例：

```nginx
server {
    listen 443 ssl http2;
    server_name dm.example.com;

    ssl_certificate     /etc/ssl/dm.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/dm.example.com/privkey.pem;

    client_max_body_size 110m;

    location / {
        proxy_pass http://127.0.0.1:10120;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
```

如果用于 ACME HTTP-01 的内置服务器需要通过 Nginx 暴露 80 端口，请单独配置 `/.well-known/acme-challenge/` 的转发，或使用 Webroot 模式，避免与现有站点冲突。

---

## 从源码构建

### 构建环境（仅构建时需要）

- Go 1.24 或更新版本
- Node.js 20+ / npm（仅用于构建前端）

### Makefile

```bash
make frontend          # 构建前端到 web/dist
make build             # 构建当前平台 ./domain-manager
make build-linux-amd64 # 构建 dist/domain-manager-linux-amd64
make build-linux-arm64 # 构建 dist/domain-manager-linux-arm64
make release           # 同时构建 amd64 / arm64 并生成 checksums.txt
make test              # 执行 Go 测试

# 没有 make 的环境也可直接运行：
./scripts/build-release.sh
make vet               # go vet
make clean             # 清理二进制与 dist
```

构建命令使用 `CGO_ENABLED=0`，SQLite 使用纯 Go 驱动，因此交叉编译不依赖系统 gcc 或 CGO。

最终产物：

```text
dist/
├── domain-manager-linux-amd64
├── domain-manager-linux-arm64
└── checksums.txt
```

部署时只需要上传对应架构的二进制文件。

### systemd 部署

仓库中的 `scripts/install.sh` 和 `scripts/domain-manager.service` 提供了 Linux 安装示例。也可以手动：

```bash
sudo mkdir -p /opt/domain-manager
sudo cp dist/domain-manager-linux-amd64 /opt/domain-manager/domain-manager
sudo chmod +x /opt/domain-manager/domain-manager
cd /opt/domain-manager && sudo ./domain-manager
```

---

## 域名监控说明

### RDAP 与 WHOIS

- 系统从 IANA RDAP Bootstrap 获取 TLD 对应的 RDAP 服务，并缓存 24 小时
- 常见 TLD（`.com`、`.net`、`.org`、`.cn`、`.io`、`.dev`、`.app`、`.xyz`、`.top`、`.vip`、`.cc` 等）会优先使用 RDAP
- RDAP 未返回到期日期、限流或服务不可用时，自动回退到 WHOIS TCP 43 查询
- 外部查询设置超时，目标地址受 SSRF 防护限制
- 查询失败原因保存在域名记录的 `last_error` 中，域名状态显示“查询失败”
- **查询失败不等同于域名过期**

### 手动设置到期时间

某些 ccTLD 或注册局策略可能限制公开查询。可以在域名编辑弹窗中开启“手动锁定到期时间”，系统之后会保留该日期，不再被自动查询覆盖。关闭手动锁定后，下一次检测会重新尝试自动查询。

### 批量导入格式

CSV / TXT 每行一条：

```csv
domain,expires_at,notes
example.com,2027-12-01,主域名
www.example.com,,
```

- 第一列：域名（必填）
- 第二列：到期日期 `YYYY-MM-DD`（可选）
- 第三列：备注（可选）
- 首行表头可省略；支持 UTF-8 BOM
- 单次最多 1000 条，文件最大 2MB

导入后可自动触发检测。

---

## SSL 证书监控说明

- 默认检测 `https://域名:443`
- 支持自定义端口与 SNI
- 使用系统根证书校验证书链；证书链或域名校验失败显示“证书异常”
- 如果 TLS 握手成功但 HTTP 请求失败，显示“HTTPS 不可访问”
- 如果证书已过期，优先显示“已过期”
- “跳过证书校验”只用于诊断，仍会采集证书信息，但不会因链或域名不匹配而标记为证书异常
- 所有 HTTP/TLS 连接均经过内网地址防护（默认禁止私网、回环、链路本地、保留地址）

### 状态定义

| 状态 | 说明 |
|---|---|
| `normal` | 证书有效、链和域名匹配、HTTPS 可访问 |
| `expiring` | 在证书预警天数内 |
| `expired` | 证书已过期 |
| `unreachable` | HTTPS 无法建立连接或请求失败 |
| `invalid` | 证书链无效或证书域名不匹配 |
| `failed` | 证书信息无法解析或检测异常 |
| `pending` | 尚未检测 |

---

## ACME 证书申请

> **重要：申请证书需要你拥有域名控制权，并具备公网验证条件。** 系统无法替代 DNS 解析、端口映射或 Web 服务器配置。没有真实验证条件时，申请会失败，系统不会伪造成功状态。

### 首次使用建议

1. 在「系统设置 → ACME 与部署」设置 ACME 邮箱
2. 在「证书申请」页面保持 **Staging** 环境
3. 选择 HTTP-01 或 DNS-01，确认验证条件
4. 成功签发测试证书后，再切换 Production 重新申请
5. 生产环境注意 Let's Encrypt 速率限制，不要频繁重试失败订单

### HTTP-01

Let's Encrypt 会从公网访问：

```text
http://<域名>/.well-known/acme-challenge/<token>
```

支持两种模式：

#### Standalone（内置验证服务器）

系统在验证时临时监听配置的地址和端口（默认 `:80`）。要求：

- 服务器公网可达，且 80 端口没有被其他 Web 服务器占用
- 域名 A/AAAA 记录指向本机
- 如通过 NAT/负载均衡映射端口，需确保外部 80 可到达

如果程序没有权限绑定 80 端口，请使用 `setcap`、以 root 运行，或改用 Webroot 模式。

#### Webroot

系统将验证文件写入：

```text
<webroot>/.well-known/acme-challenge/<token>
```

要求现有 Web 服务器将 `/.well-known/acme-challenge/` 映射到该目录，并且外部可访问。系统**不会**自动修改 Nginx/Apache 配置。

### DNS-01

系统会真实调用 DNS 服务商 API：

1. 创建 `_acme-challenge.<域名>` TXT 记录
2. 通过公共 DNS 检查记录传播
3. 等待 ACME 服务器验证
4. 清理 TXT 记录

支持：

| Provider | 必填配置 | 说明 |
|---|---|---|
| Cloudflare | `api_token` | Token 需具备 Zone:Read 与 DNS:Edit 权限；可选 `zone_id` / `zone` |
| DNSPod / 腾讯云 | `secret_id`、`secret_key` | 可选 `region`、`zone` |
| 阿里云 DNS | `access_key_id`、`access_key_secret` | 可选 `zone` |

泛域名如 `*.example.com` 必须使用 DNS-01。建议同时添加根域名 `example.com`。

DNS 凭据会使用 AES-GCM 加密后存入数据库，API 和页面不会回显明文。

DNS Provider 采用注册表插件结构：实现 lego 的 `challenge.Provider` 后调用 `dns.RegisterProvider(name, validate, factory)` 即可注册新的服务商，无需修改 ACME 主流程。

### 自动续期

- 调度器每天检查一次（频率可修改）
- 对 `auto_renew=true` 的 ACME 托管证书，在到期前 `acme_renew_days` 天（默认 30 天）创建新订单
- 续期复用原订单的验证方式、DNS Provider 和加密凭据
- 续期成功后旧订单标记为 `renewed`
- 失败订单按指数退避重试（默认 6h、12h，最多 3 次），避免违反 CA 限流
- 达到最大尝试次数后需要管理员排查并手动处理

### 证书下载与部署

签发成功后，文件保存在：

```text
data/certs/<certificate-id>/
├── cert.pem
├── chain.pem
├── fullchain.pem
└── privkey.pem       # 0600
```

- 私钥不会在列表或详情 API 中返回
- 下载私钥必须在界面中明确确认，下载响应使用 `no-store`
- “部署”会将文件复制到 `deploy_dir/<域名>/`，私钥仍为 0600
- 可配置部署脚本（绝对路径），通过环境变量获取文件路径：

```text
CERT_DOMAIN
CERT_DIR
CERT_FULLCHAIN
CERT_PRIVKEY
CERT_CERT
CERT_CHAIN
```

脚本不会通过 Shell 拼接执行。示例：

```bash
#!/usr/bin/env bash
set -euo pipefail
install -d -m 0750 /etc/nginx/ssl/example.com
install -m 0644 "$CERT_FULLCHAIN" /etc/nginx/ssl/example.com/fullchain.pem
install -m 0600 "$CERT_PRIVKEY" /etc/nginx/ssl/example.com/privkey.pem
# 只有授予 reload 权限后才能执行；见下方说明。
nginx -t
```

系统不会假设或自动修改你的 Nginx/Apache 配置。部署脚本只继承 `PATH` 和 `CERT_*` 环境变量，不会读取 `DM_ADMIN_PASSWORD` 等进程密钥。

仓库中的 systemd 单元使用非 root 用户并设置了 `NoNewPrivileges=true`，因此脚本内直接执行 `systemctl reload nginx` 会失败。任选一种安全方案：

1. **推荐：systemd path 单元**。部署脚本只负责复制文件，另建一个以 root 运行的 `.path` 单元监听 `deploy_dir`，触发 `nginx -t && systemctl reload nginx`。
2. 为 `domain-manager` 用户配置 polkit 规则，只允许该用户 reload nginx。
3. 在 sudoers 中仅授权 `domain-manager ALL=(root) NOPASSWD: /bin/systemctl reload nginx`，同时从服务单元移除 `NoNewPrivileges=true`（会降低隔离强度，需自行评估）。

如果部署脚本直接写 `/etc/nginx/ssl`，还需把该目录加入 systemd 的 `ReadWritePaths` 并授予运行用户写权限。

如果使用仓库中的 systemd 服务单元，默认只允许写入 `/opt/domain-manager/data`、`logs`、`configs`。当 `deploy_dir` 指向 `/etc/nginx/ssl` 等其他目录时，请同步将该目录加入 systemd 的 `ReadWritePaths`，并确保运行用户有写权限。

---

## 通知配置

### Telegram

- 通过 @BotFather 创建 Bot，获取 Bot Token
- 将 Bot 加入目标群组，获取 Chat ID（群组 ID 通常为负数）
- 可选 Topic ID（论坛群组话题）
- 使用 Telegram Bot API `sendMessage`，HTML 格式

### Lark / 飞书

- 群机器人设置中获取 Webhook URL
- 如启用签名校验，填写签名密钥
- 支持文本与交互式消息卡片
- Lark 国际版与飞书国内版接口可能存在差异，可关闭消息卡片使用文本模式

### 钉钉

- 群设置 → 智能群助手 → 自定义机器人
- 获取 Webhook URL
- 如启用“加签”，填写 Secret
- 使用 Markdown 消息

### 去重与恢复

- 域名告警去重键：域名 ID + 阈值 + 到期日期
- SSL 告警去重键：证书 ID + 阈值 + 到期日期
- 相同阈值不会重复发送；进入更小阈值时会再提醒
- 去重窗口设为 0 表示永久去重
- 域名续费或证书续期后，若不再满足预警条件，会发送恢复通知
- 通知发送失败会记录日志并按设置重试

### 默认告警阈值

域名：30 / 15 / 7 / 3 / 1 / 0 天（0 表示到期当天）  
SSL：30 / 15 / 7 / 3 / 1 天，到期当天也会触发过期告警

均可在「系统设置 → 基础配置」中修改。

---

## 定时任务

| 任务 | 默认频率 | 说明 |
|---|---|---|
| 域名到期检查 | 每天 03:00 | 查询所有启用监控的域名 |
| SSL 证书检查 | 每 6 小时 | 检测所有启用监控的 HTTPS 端点 |
| 证书续期检查 | 每天 04:00 | 为临近到期的托管证书创建续期订单 |
| 告警扫描 | 每小时 | 根据阈值触发通知与恢复通知 |
| 通知失败重试 | 每 10 分钟 | 重试失败的发送记录 |
| ACME 订单队列 | 每 5 分钟 | 处理排队、中断与到期重试订单 |

特点：

- 配置保存在数据库中，重启后自动恢复
- 同一任务不会并发执行
- 每个任务有执行记录（`job_runs`）
- 单个域名/证书有内存级并发保护，避免重复检测
- 所有外部请求都有超时
- 最大检测并发数可配置
- 任务异常会记录日志，并可发送“系统异常”通知

---

## 安全设计

- 首次运行初始化管理员，随机密码，终端仅输出一次
- 密码使用 bcrypt（cost 12）哈希存储
- 登录失败限制（IP+用户名）与账号锁定
- 支持 TOTP 二次认证：密钥使用 AES-GCM 加密存储，恢复码仅保存哈希且只能使用一次
- TOTP 登录采用短时挑战令牌，验证通过前不会创建会话，并拒绝重放同一时间步的验证码
- 会话使用随机 256-bit Token，HttpOnly + SameSite=Strict Cookie
- 修改密码后所有会话失效
- 所有写操作要求 CSRF Token；GET 请求不修改状态
- 统一 CSP、X-Frame-Options、nosniff、Referrer-Policy 等安全响应头
- 默认不信任代理；仅在配置 `trusted_proxies` 后读取转发头
- 外部域名、HTTPS、RDAP、WHOIS、Webhook 请求均有内网/保留地址防护
- Webhook 必须使用 HTTPS（端口 443/8443），并校验解析后的公网 IP
- 允许监控内网地址默认关闭，开启后明确提示 SSRF 风险
- 通知 Token、Webhook 密钥使用 AES-GCM 加密存储，API 返回脱敏值
- ACME DNS 凭据加密存储，私钥与账号密钥文件 0600
- 证书私钥不在列表/详情 API 中，不写日志；下载需要显式确认
- 下载、部署等敏感操作写入监控日志
- 上传 CSV 限制扩展名、大小与数量；数据库恢复校验 SQLite 文件头、表结构与完整性
- 数据库使用 WAL、busy_timeout、最大连接数限制，降低 SQLite 写锁冲突
- 支持数据库在线备份和恢复

### 生产环境建议

- 必须通过 HTTPS 反向代理访问，并设置 `cookie_secure: true`
- 不要直接将未授权的管理后台暴露到公网
- 定期下载数据库备份
- 部署目录与部署脚本仅授予必要权限
- DNS API 凭据使用最小权限
- 为 Let's Encrypt 生产环境设置合理重试策略，避免触发限流
- 配置日志轮转（内置按 50MB / 30 天轮转）

---

## 数据库

默认位置：`./data/domain-manager.db`。

主要数据表：

| 表 | 说明 |
|---|---|
| `domains` | 域名、注册商、到期时间、监控状态 |
| `ssl_certificates` | HTTPS 端点、证书信息、本地证书路径、续期开关 |
| `notification_channels` | 通知渠道及加密配置 |
| `notification_rules` | 事件与渠道绑定、去重策略 |
| `notification_logs` | 通知发送记录与重试状态 |
| `monitor_logs` | 域名/SSL/部署/下载等执行日志 |
| `acme_accounts` | ACME 账号元数据与账号密钥路径 |
| `certificate_orders` | 证书订单、日志、重试状态 |
| `system_settings` | 系统配置 |
| `scheduled_jobs` | 定时任务定义与最近状态 |
| `job_runs` | 定时任务执行历史 |
| `alert_states` | 告警去重与恢复状态 |
| `users` | 管理员账号、密码哈希、TOTP 加密密钥与恢复码哈希 |
| `schema_migrations` | 数据库版本迁移记录 |

### 备份与恢复

- 后台「系统设置 → 备份与恢复」可下载 SQLite 在线一致性快照
- 数据库备份包含数据库内容，**不包含** `secret.key`、`data/certs/`、`data/acme/` 中的密钥文件；跨实例恢复时，通知渠道密钥与 TOTP 密钥可能因加密密钥不同而无法解密，完整备份可避免此问题
- 「完整备份」会打包整个 `data/`（数据库快照、`secret.key`、证书私钥、ACME 账号），并用口令加密为 `.dmbak` 文件。**备份文件与口令同时泄露等同于泄露全部 DNS 凭据和通知密钥**，请分开保管
- 恢复会暂停定时任务、覆盖当前数据并强制所有管理员重新登录；完整备份会替换 `secret.key` 并自动重新加载
- 数据库恢复按列名取交集，兼容旧版本备份缺少新列的情况
- 恢复文件接受 `.db` / `.sqlite` / `.sqlite3` / `.dmbak`，并校验 SQLite 完整性或完整备份格式

---

## REST API

统一前缀：`/api/v1`

认证方式：登录后服务端设置 `dm_session` HttpOnly Cookie。写请求必须携带登录返回的 `csrf_token`：

```http
X-CSRF-Token: <csrf_token>
```

统一响应：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

HTTP 状态码表达结果（400/401/403/404/409/429/500）。

启用 TOTP 后，密码校验通过时 `POST /auth/login` 返回 `totp_required: true` 与短时 `challenge_token`，此时不会设置会话 Cookie；随后调用 `POST /auth/login/totp` 提交 `challenge_token` 和 `code`（动态验证码或一次性恢复码）完成登录。

### 主要接口

```text
POST   /api/v1/auth/login
POST   /api/v1/auth/login/totp
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
PUT    /api/v1/auth/password
POST   /api/v1/auth/totp/setup
POST   /api/v1/auth/totp/enable
POST   /api/v1/auth/totp/disable
POST   /api/v1/auth/totp/recovery-codes

GET    /api/v1/dashboard

GET    /api/v1/domains
POST   /api/v1/domains
GET    /api/v1/domains/:id
PUT    /api/v1/domains/:id
DELETE /api/v1/domains/:id
POST   /api/v1/domains/:id/check
POST   /api/v1/domains/check-all
POST   /api/v1/domains/import

GET    /api/v1/certificates
POST   /api/v1/certificates
GET    /api/v1/certificates/:id
PUT    /api/v1/certificates/:id
DELETE /api/v1/certificates/:id
POST   /api/v1/certificates/check
POST   /api/v1/certificates/:id/check
POST   /api/v1/certificates/apply
POST   /api/v1/certificates/:id/renew
POST   /api/v1/certificates/:id/deploy
GET    /api/v1/certificates/:id/download?type=fullchain

GET    /api/v1/orders
POST   /api/v1/orders/:id/retry
GET    /api/v1/acme/accounts

GET    /api/v1/notifications
POST   /api/v1/notifications
PUT    /api/v1/notifications/:id
DELETE /api/v1/notifications/:id
POST   /api/v1/notifications/:id/test
GET    /api/v1/notification-rules
PUT    /api/v1/notification-rules

GET    /api/v1/logs/monitor
GET    /api/v1/logs/notification

GET    /api/v1/settings
PUT    /api/v1/settings

GET    /api/v1/system/status
POST   /api/v1/system/backup
POST   /api/v1/system/restore

GET    /api/v1/jobs
POST   /api/v1/jobs/:key/run
GET    /api/v1/jobs/runs
```

分页参数：`page`、`page_size`（最大 100）。

---

## 项目结构

```text
domain-manager/
├── cmd/server/main.go          # 启动、依赖装配、优雅退出
├── internal/
│   ├── api/                    # Gin 路由、认证、CSRF、API handler
│   ├── auth/                   # 登录、密码、会话策略
│   ├── acme/                   # ACME 申请/续期/账号/日志
│   │   └── dns/                # Cloudflare / DNSPod / AliDNS Provider
│   ├── certificate/            # PEM 文件、下载、部署
│   ├── config/                 # YAML/环境变量配置
│   ├── database/               # SQLite 初始化、迁移、种子、备份恢复
│   ├── logger/                 # 结构化日志与轮转
│   ├── monitor/                # RDAP/WHOIS/SSL 检测
│   ├── notification/           # 通知 Provider、重试、去重
│   ├── scheduler/              # Cron 调度、告警扫描
│   ├── security/               # SSRF、加密、密码、会话、CSRF
│   └── settings/               # 系统设置
├── frontend/                   # Vue 3 + TypeScript + Vite
├── web/
│   ├── embed.go                # go:embed 前端静态资源
│   └── dist/                   # 构建后的前端
├── configs/
├── data/
├── logs/
├── scripts/
├── Makefile
├── go.mod
└── README.md
```

---

## 测试

```bash
make test
```

测试覆盖包括：

- 域名规范化、SSRF 公网地址判断（含 NAT64）、密钥脱敏、中文按 rune 截断
- RDAP / WHOIS 响应解析、日期解析、域名状态
- 通知配置脱敏与掩码合并
- 数据库迁移幂等、备份 / 恢复往返、完整备份加密与恢复、旧备份列兼容
- 登录限流按用户名 + IP、未知用户计时、首次登录强制改密
- TOTP 算法（RFC 6238 向量）、挑战登录、恢复码一次性使用、重放拒绝
- ACL / CSRF（含 public_url 白名单）/ 域名 API / Dashboard API 集成测试
- ACME 续期重试耗尽后的冷却、日志保留清理
- 部署脚本环境隔离、目录原子切换
- SPA 静态资源回退与 gzip 压缩
- 本地 TLS 证书检测、内网目标拒绝
- 告警阈值选择
- DNS Provider 配置校验

### 关于 ACME 集成测试

ACME 申请代码使用真实 `go-acme/lego` 客户端，会真实连接 Let's Encrypt。完整签发测试需要：

- 一个你可控制的公网域名
- HTTP-01 的公网 80 端口，或
- 云 DNS API 凭据与 DNS-01 权限

因此本仓库无法在没有上述资源的环境中伪造“成功签发”结果。建议先使用 Staging 环境，在「证书申请」页面提交自己的域名进行验证；失败订单会保留真实错误日志，不会伪造成功状态。

---

## 常见问题

### 域名一直显示“查询失败”

- 该 TLD 可能不提供 RDAP
- WHOIS 服务器可能限流、屏蔽或缺少到期字段
- 检查服务器能否访问外网 TCP 43 / HTTPS
- 可在域名编辑中手动锁定到期时间

### SSL 检测显示“HTTPS 不可访问”

- 检查域名解析、443 端口、防火墙
- 如果服务器使用非标准端口，请在证书监控中修改端口
- 如果使用 CDN，请确认回源与 SNI 配置

### ACME HTTP-01 失败

- Let's Encrypt 始终访问公网 80，不是后台配置的其它端口
- 80 端口必须能到达本机，或 Webroot 必须被 Web 服务器正确暴露
- 检查域名 A/AAAA 记录和 NAT 转发

### ACME DNS-01 失败

- 检查 DNS API 凭据权限与区域
- 检查 `_acme-challenge` TXT 是否成功写入并传播
- 某些 DNS 服务商存在 TTL/解析生效延迟
- Cloudflare Token 需要 Zone:Read 与 DNS:Edit

### 登录密码丢失

停止服务后删除 `data/domain-manager.db` 会丢失全部数据，不建议这样做。可以在备份数据库后，使用 SQLite 工具删除 `users` 表对应记录，重启会重新生成管理员；或从备份恢复。请务必先备份。

### 二次认证设备丢失

优先使用启用二次认证时保存的一次性恢复码登录，然后在「系统设置 → 安全设置」中重新生成恢复码或关闭二次认证。若恢复码也已丢失，可在备份数据库后使用 SQLite 工具将 `users` 表中的 `totp_enabled`、`totp_secret`、`totp_recovery_codes` 清空，重启后即可仅用密码登录；操作前请务必备份。不要直接删除数据库。

### 通知测试失败

- 确认 Webhook URL 可被服务器访问
- 确认签名密钥与平台一致
- Telegram 需要 Bot Token 与 Chat ID 正确
- 查看「监控日志 → 通知发送日志」中的错误详情

---

## License

本项目为交付源码，未附带特定开源许可证。请在符合所在组织与第三方依赖许可证的前提下使用。
