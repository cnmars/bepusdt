# BEpusdt 项目分析报告 & 安全评估

> 分析日期: 2026-06-24
> 项目: https://github.com/cnmars/bepusdt
> 分支: main / commit: 827bc48

---

## 一、项目概述

**BEpusdt**（Better Easy Payment USDT）是一个**自托管个人加密货币收款网关**，使用 **Go (Golang)** 编写后端，**Vue 3 + TypeScript** 编写管理后台前端。允许个人/商户接受 USDT、USDC、TRX、BNB、ETH、TON 等加密货币支付，覆盖 **11+ 条区块链网络**，无需第三方支付处理商。

### 核心功能

| 功能 | 说明 |
|------|------|
| 多链收款 | Tron TRC20, Ethereum ERC20, BSC BEP20, Polygon, Arbitrum, Solana, Aptos, TON, X-Layer, Plasma, Base |
| 实时链上扫描 | 自动扫描区块链交易，匹配订单（EVM gRPC/JSON-RPC、Tron gRPC、Solana RPC、Aptos REST、TON Liteserver） |
| 智能匹配 | 支持精确匹配、前缀匹配、四舍五入匹配三种模式 |
| 异步回调 | 兼容 EPusdt（JSON POST）和易支付/彩虹易支付（Query String GET）两种回调格式 |
| 通知渠道 | Telegram Bot 通知（订单成功、回调失败、非订单转账、Tron 资源变更） |
| MQTT 广播 | 实时交易事件推送 |
| 管理后台 | 钱包管理、订单管理、汇率管理、RPC 节点监控、仪表盘统计 |
| 多数据库 | SQLite（内置）、MySQL、PostgreSQL |
| 一键部署 | 单二进制文件、Docker 容器 |

### 技术栈

| 层级 | 技术 |
|------|------|
| 后端语言 | Go 1.26.2 |
| Web 框架 | Gin + gin-contrib/sessions |
| ORM | GORM（SQLite / MySQL / PostgreSQL） |
| 前端框架 | Vue 3.5 + TypeScript + Arco Design + Vite 7 |
| 状态管理 | Pinia |
| 图表 | ECharts 6 |
| 其他 | Logrus（日志）、go-nanoid（ID生成）、shopspring/decimal（高精度计算）、ants（协程池） |

---

## 二、架构分析

### 目录结构

```
bepusdt/
├── main/main.go          # 入口：加载 .env、解析 CLI 命令
├── app/
│   ├── cmd/              # CLI 命令处理器（start/reset/version）
│   ├── conf/             # 常量定义、RPC 健康统计
│   ├── core/             # 外部 API 客户端（api.bepusdt.online）
│   ├── handler/          # HTTP 请求处理器
│   │   ├── admin/        # 管理后台 API
│   │   ├── auth/         # 认证 API（登录/登出/改密）
│   │   ├── epusdt/       # EPusdt 兼容 API
│   │   ├── epay/         # 易支付兼容 API
│   │   └── base/         # 基础请求/响应类型
│   ├── log/              # 日志模块（Logrus + Lumberjack 轮转）
│   ├── model/            # 数据模型 + ORM 操作
│   ├── mqtt/             # MQTT 客户端
│   ├── notifier/         # 通知渠道（Telegram/微信/无）
│   ├── router/           # 路由注册 + 中间件
│   ├── task/             # 后台定时任务（区块链扫描、订单匹配、回调重试）
│   │   └── notify/       # HTTP 回调投递
│   └── utils/            # 工具函数（签名、地址校验、哈希等）
├── static/               # 内嵌静态资源（管理后台 SPA、收银台模板）
└── web/                  # Vue 3 前端源码
```

### 数据流

```
商户系统 → HTTP API（创建订单） → BEpusdt → 数据库存储
                                                  ↓
区块链 RPC 节点 ← 定时扫描任务 ← 读取待支付订单
        ↓
    交易数据 → 转账队列 → 订单匹配引擎 → 标记确认中
                                            ↓
                                      交易确认 → 回调成功 → 通知商户
                                            ↓
                                      Telegram 通知 / MQTT 广播
```

---

## 三、安全评估

### 3.1 高危漏洞

#### H-01: 回调 URL 未限制内网地址（SSRF）

**文件**: `app/utils/utils.go:210-224` (`IsAllowedCallbackURL`), `app/task/notify/notify.go`

**描述**: `IsAllowedCallbackURL` 只校验 URL 格式（必须是 `http` 或 `https` 协议、Host 非空），但**未阻止指向内网 IP 的 URL**（如 `http://127.0.0.1:8545`、`http://10.0.0.1:6379`、`http://[::1]:22` 等）。攻击者可通过创建订单时提交恶意 `notify_url`，诱导 BEpusdt 服务器向内部服务发起 HTTP 请求，可能导致 SSRF 攻击。

**影响**: 
- 探测内网端口和服务
- 攻击内部 RPC 节点、数据库、Redis 等
- 可能利用内网服务的未授权接口

**建议修复**:
```go
func IsAllowedCallbackURL(raw string) bool {
    u, err := url.ParseRequestURI(raw)
    if err != nil { return false }
    if u.Scheme != "http" && u.Scheme != "https" { return false }
    if u.Host == "" { return false }
    // 解析 IP，阻止内网地址
    host := u.Hostname()
    if ip := net.ParseIP(host); ip != nil {
        if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
            return false
        }
    }
    // 阻止内网域名解析（需配合 DNS 检查）
    return true
}
```

#### H-02: API 鉴权令牌明文存储

**文件**: `app/model/conf.go:154` (`ApiAuthToken`), `app/handler/epusdt/epusdt.go:94`

**描述**: API 对接令牌 `ApiAuthToken` 以明文形式存储在数据库 `bep_conf` 表中。任何能够读取数据库的人（SQL 注入、文件泄露、备份泄露等）都可以获取完整令牌，进而通过 API 创建订单、查询订单、取消订单。

**影响**:
- 攻击者可伪造 API 请求创建欺诈订单
- 可查询/取消任意订单
- 签名验签被绕过

**建议修复**: 存储令牌的 SHA-256 哈希，验证时比对哈希值。

#### H-03: 管理端 API 缺少 CSRF 保护

**文件**: `app/router/router.go:108-112`

**描述**: 管理后台 API 依赖 HTTP Header `Authorization` 中的 Bearer Token 进行鉴权。虽然 Session Cookie 设置了 `SameSite=StrictMode`，但整个管理后台 API 没有 CSRF Token 机制。Iframe/页面嵌入场景下可能遭受跨站请求伪造。

**建议修复**: 为写操作添加 CSRF Token 校验。

#### H-04: RPC 端点配置可指向恶意节点

**文件**: `app/handler/admin/conf.go:118-145`, `app/task/evm.go` 及各类扫描器

**描述**: 管理员可配置 RPC 端点 URL。如果攻击者获得管理员权限，可将 RPC 端点指向恶意节点，从而：
- 返回伪造的交易数据，触发虚假的支付确认
- 实施 SSRF 攻击
- 窃取链上数据

**影响**: 恶意 RPC 节点可导致资金欺诈（虚假到账确认）。

**建议修复**: 
- 支持 RPC 端点白名单
- 对 RPC 响应做多重验证
- 记录 RPC 端点变更审计日志

---

### 3.2 中危漏洞

#### M-01: 登录接口无速率限制

**文件**: `app/handler/auth/auth.go:320-352`

**描述**: `/api/auth/login` 接口没有 IP 级别的速率限制。攻击者可以对管理员密码进行暴力破解。

**建议修复**: 实现基于 IP 的登录频率限制，失败 N 次后锁定账户/IP。

#### M-02: MD5 用于 API 签名

**文件**: `app/utils/utils.go:39-68` (`EpusdtSign`)

**描述**: MD5 已被证明存在碰撞攻击风险。虽然当前场景下利用碰撞攻击签名验证的难度较高，但不推荐在安全敏感场景使用 MD5。

**建议修复**: 替换为 HMAC-SHA256：

```go
func EpusdtSign(data map[string]interface{}, token string) string {
    // 排序拼接
    // ...
    mac := hmac.New(sha256.New, []byte(token))
    mac.Write([]byte(signString))
    return hex.EncodeToString(mac.Sum(nil))
}
```

#### M-03: Session 密钥强度不可控

**文件**: `app/router/router.go:26`

**描述**: `memstore.NewStore([]byte(model.GetK(model.AdminSecret)))` 使用 `AdminSecret` 直接作为加密密钥。
`AdminSecret` 是 SHA-256 输出（32 字节），但 `memstore` 的实现可能会根据密钥长度选择不同的加密算法（如 AES-128 需要 16 字节密钥，AES-256 需要 32 字节密钥）。密钥长度不匹配时可能会被截断或补零。

**建议修复**: 使用固定且足够强度的密钥，参考：
```go
secret := sha256.Sum256([]byte(model.GetK(model.AdminSecret)))
store := memstore.NewStore(secret[:])
```

#### M-04: LIKE 查询中的通配符泄露

**文件**: `app/handler/admin/wallet.go:91-98`, `app/handler/admin/order.go:122-145`

**描述**: 多个查询使用 `LIKE ?` + `%` 拼接用户输入。虽然 GORM 参数化查询防止了 SQL 注入，但用户输入中的 `%` 和 `_` 通配符不会被转义，可能导致信息泄露（通过布隆过滤或响应差异）。

**示例**: 查询 `order_id LIKE ?` + `%` + `"order_%"` + `%` 会匹配额外结果。

**建议修复**: 对用户输入的 LIKE 通配符进行转义：
```go
func escapeLike(s string) string {
    s = strings.ReplaceAll(s, "_", "\\_")
    s = strings.ReplaceAll(s, "%", "\\%")
    return s
}
```

---

### 3.3 低危漏洞 / 安全注意事项

#### L-01: 首次安装凭据输出到 stdout

**文件**: `app/model/conf.go:169-193`

**描述**: 首次初始化的管理员用户名、密码、安全入口、API 令牌全部明文输出到控制台 stdout。如果日志被采集系统（如 systemd journal、Docker logs、日志聚合平台）捕获，凭据可能泄露。

**建议**: 添加启动参数 `--hide-creds` 禁止输出敏感信息，仅写入日志文件并提示用户查看。

#### L-02: 无 HTTPS 强制

**文件**: 全局

**描述**: 应用默认监听 HTTP。虽然在 `GetRequestHost` 中尝试检测 TLS 和代理协议头，但没有强制 HTTPS 的机制。API 令牌和密码在网络中明文传输的风险。

**建议**: 添加 TLS 配置选项，或建议用户使用反向代理（Nginx/Caddy）终止 TLS。

#### L-03: 调试模式缺少访问控制

**文件**: `app/router/router.go:73-76`

**描述**: 当 `conf.Debug` 为 true 时，所有鉴权中间件被跳过。如果生产环境错误启用了 Debug 模式，管理后台完全无保护。

**建议**: Debug 模式也应当校验基本的访问控制，添加安全警告日志。

#### L-04: YAML 反序列化（gjson 安全使用）

**文件**: `app/task/evm.go` 及其他扫描器

**描述**: 使用 `gjson` 解析来自外部 RPC 节点的 JSON 响应。gjson 本身是安全的读取库（不执行任意代码），但恶意 RPC 节点可返回超大 JSON 引发内存问题。

**建议**: 添加响应体大小限制（如 `io.LimitReader(resp.Body, 10<<20)`）。

#### L-05: 配置键未经严格校验

**文件**: `app/handler/admin/conf.go:35-48`

**描述**: `Conf.Set` 和 `Conf.Sets` 接口接收任意字符串作为配置键，写入数据库。虽然需要管理员权限，但缺乏合法性校验可能导致意外覆盖或创建无关配置项。

**建议**: 维护可选配置键白名单，拒绝非法键。

#### L-06: 区块链扫描无速率限制保护

**文件**: `app/task/evm.go`, `app/task/tron.go`, 等

**描述**: 区块链扫描任务会频繁调用 RPC 节点。若 RPC URL 被指向恶意节点或无限制使用免费公共节点，可能触发 IP 封禁或服务降级。

**建议**: 内置请求速率限制（目前 TON 和 Aptos 已有部分限制，但 EVM 和 Tron 缺少）。

---

### 3.4 安全意识良好之处

值得肯定的安全设计：

1. **密码使用 bcrypt 存储** (`app/handler/auth/auth.go:336`) — 正确的密码哈希方案。
2. **ConstantTimeCompare 验证 Token** (`app/router/router.go:108`) — 防止时序攻击。
3. **Session Cookie HttpOnly + SameSite=Strict** (`app/router/router.go:29-30`) — 降低 XSS/CSRF 风险。
4. **GORM 参数化查询** — 全局使用参数化查询防止 SQL 注入。
5. **地址格式校验** — 各区块链地址格式有针对性校验函数。
6. **超时控制** — HTTP 回调使用 `context.WithTimeout` 防止阻塞。
7. **订单过期机制** — 自动过期未支付订单，防止无限等待。
8. **缓存防重放通知** (`app/task/notify/notify.go:192-197`) — 使用内存缓存防止重复通知。
9. **Go Embed 安全** — 静态资源直接编译进二进制文件，防止文件篡改。

---

## 四、代码质量评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 代码组织 | ★★★★☆ | 分层清晰，模块划分合理，命名统一 |
| 错误处理 | ★★★★☆ | 大部分错误被妥善处理，部分函数省略了错误检查 |
| 并发安全 | ★★★★☆ | 使用 sync.Map、channel、ants 协程池，状态管理清晰 |
| 类型安全 | ★★★☆☆ | Go 类型系统利用良好，但部分地方使用 `interface{}` |
| 可测试性 | ★★★☆☆ | 缺少单元测试和集成测试 |
| 文档覆盖 | ★★★☆☆ | README 详细，API 文档存在但部分功能文档缺失 |
| 国际化 | ★★★☆☆ | 收银台模板支持 i18n，管理后台部分只有中文 |
| 依赖管理 | ★★★★☆ | go.mod 管理清晰，前端 package.json 使用 ^ 版本范围 |

核心亮点：
- 支持 11+ 区块链网络，代码复用度高（EVM 通用扫描器）
- 单二进制部署，零外部依赖（SQLite 内嵌）
- 协程池和 channel 高效管理并发任务
- 支持三种订单匹配模式，灵活应对实际场景

---

## 五、总结

BEpusdt 是一个功能全面的自托管加密货币收款网关，架构设计合理，代码质量良好。在多链支持、订单匹配、回调通知等方面表现出色，且具备良好的安全基础（bcrypt、参数化查询、ConstantTimeCompare 等）。

### 关键风险（需优先处理）

| 优先级 | 风险 | 类别 |
|--------|------|------|
| **P0** | 回调 URL SSRF（未限制内网地址） | 高危 |
| **P0** | API 令牌明文存储 | 高危 |
| **P1** | 无 CSRF 防护 | 中危 |
| **P1** | 登录无速率限制 | 中危 |
| **P2** | MD5 签名算法过时 | 中危 |
| **P2** | LIKE 通配符未转义 | 中危 |

### 总体安全评分

**B+ (良好)**

项目具备基本安全防护，核心加密和认证方案正确。主要风险集中在 SSRF 和敏感信息存储两方面，修复这些后安全性将达到良好水平。

---

*本报告由自动化安全分析生成，仅供参考。建议在实际部署前进行全面安全审查。*
