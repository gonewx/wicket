# 外部认证提供者配置指南

## 概述

Wicket 支持多种外部身份提供者（IdP），允许用户通过第三方账号登录。外部提供者分为两类：

1. **OAuth 认证处理器**（`auth/google`、`auth/facebook`、`auth/jwt`）— 处理完整的 OAuth 授权码流，将外部用户映射为本地 Claims
2. **OIDC 令牌验证器**（`oidcverify`）— 验证外部 IdP 签发的 ID Token（用于前端已获取令牌后由后端验证的场景）

## 架构概览

```
宿主应用
    │
    ├── ServerConfig.SetAuthenticationHandlerProvider(scheme, factory)
    │       → 注入自定义 Handler（覆盖内置默认）
    │
    ├── di/dsl_core.go 内置注册
    │       → Google / Facebook / JWT Bearer Handler
    │
    └── DynamicProviderOptions
            → 运行时动态注册方案
```

认证中间件链：
```
请求 → 动态方案中间件 → 核心认证中间件 → 端点路由
```

---

## Google

### 基本信息

| 属性 | 值 |
|------|-----|
| Scheme 名 | `Google`（`wicket.GoogleAuthenticationScheme`） |
| 显示名 | Google |
| 协议 | OAuth 2.0 授权码流 |
| 授权端点 | `https://accounts.google.com/o/oauth2/v2/auth` |
| 令牌端点 | `https://oauth2.googleapis.com/token` |
| 用户信息端点 | `https://www.googleapis.com/oauth2/v2/userinfo` |
| 回调路径 | `/signin-google` |
| 默认 Scope | `openid`、`profile`、`email` |

### 配置选项（`google.Options`）

继承自 `oauthcore.Options`，额外字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `AccessType` | `*string` | `"online"`（默认）或 `"offline"`（获取 refresh token） |

基类关键字段（`oauthcore.Options`）：

| 字段 | 说明 |
|------|------|
| `ClientId` | Google Cloud Console 分配的 Client ID |
| `ClientSecret` | 对应的 Client Secret |
| `CallbackPath` | 回调路径（默认 `/signin-google`） |
| `Scope` | 请求的权限列表 |
| `UsePkce` | 是否启用 PKCE |

### 默认 Claims 映射

| Claim Type | JSON 字段 |
|------------|-----------|
| `NameIdentifier` | `id` |
| `Name` | `name` |
| `GivenName` | `given_name` |
| `Surname` | `family_name` |
| `urn:google:profile` | `link` |
| `Email` | `email` |

### 集成示例

```go
root := di.NewRoot()
defer root.Close()

cfg := godi.GetRequired[*di.ServerConfig](root)

// Google 选项通过 Options 管道配置
// 在宿主启动时设置 ClientId/ClientSecret
// （通过 godi Options Configure 机制）

// 如需覆盖默认 Handler：
cfg.SetAuthenticationHandlerProvider(wicket.GoogleAuthenticationScheme, func(p godi.Provider) auth.Handler {
    return google.NewHandler(
        godi.GetRequired[optspkg.OptionsMonitor[*google.Options]](p),
        godi.GetRequired[*slog.Logger](p),
        godi.GetRequired[services.SystemClock](p),
    )
})
```

---

## Facebook

### 基本信息

| 属性 | 值 |
|------|-----|
| Scheme 名 | `Facebook`（`wicket.FacebookAuthenticationScheme`） |
| 显示名 | Facebook |
| 协议 | OAuth 2.0 授权码流 |
| 授权端点 | `https://www.facebook.com/v11.0/dialog/oauth` |
| 令牌端点 | `https://graph.facebook.com/v11.0/oauth/access_token` |
| 用户信息端点 | `https://graph.facebook.com/v11.0/me` |
| 回调路径 | `/signin-facebook` |
| 默认 Scope | `email` |

### 配置选项（`facebook.Options`）

| 字段 | 类型 | 说明 |
|------|------|------|
| `SendAppSecretProof` | `bool` | 是否发送 appsecret_proof（默认 `true`） |
| `Fields` | `[]string` | 从 Graph API 获取的用户字段 |

Facebook 使用 `AppId` / `AppSecret` 术语（映射到 `ClientId` / `ClientSecret`）：

```go
opts.SetAppId("your-facebook-app-id")
opts.SetAppSecret("your-facebook-app-secret")
```

### 默认请求字段

`name`、`email`、`first_name`、`last_name`

可通过 `AddFields(...)` 追加：`birthday`、`gender`、`locale`、`link`、`location`、`timezone`、`age_range` 等。

### 默认 Claims 映射

| Claim Type | JSON 字段 |
|------------|-----------|
| `NameIdentifier` | `id` |
| `Email` | `email` |
| `Name` | `name` |
| `GivenName` | `first_name` |
| `Surname` | `last_name` |
| `DateOfBirth` | `birthday` |
| `Gender` | `gender` |
| `Locality` | `locale` |
| `urn:facebook:age_range_min` | `age_range.min` |
| `urn:facebook:age_range_max` | `age_range.max` |
| `urn:facebook:middle_name` | `middle_name` |
| `urn:facebook:link` | `link` |
| `urn:facebook:location` | `location.name` |
| `urn:facebook:timezone` | `timezone` |

### 验证要求

`Options.Validate()` 强制要求 `AppId` 和 `AppSecret` 非空，否则启动失败。

---

## JWT Bearer

### 基本信息

| 属性 | 值 |
|------|-----|
| Scheme 名 | `Bearer`（`wicket.JwtBearerAuthenticationScheme`） |
| 协议 | JWT 令牌验证（非 OAuth 授权码流） |
| 用途 | 验证 API 请求中的 Bearer Token |

### 配置选项（`jwt.Options`）

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `Authority` | `string` | — | OIDC 发行者 URL（自动发现 JWKS） |
| `MetadataAddress` | `string` | — | 元数据端点（覆盖 Authority 发现） |
| `Audience` | `string` | — | 有效受众值 |
| `RequireHttpsMetadata` | `bool` | `true` | 是否要求 HTTPS 元数据 |
| `Challenge` | `string` | `Bearer` | WWW-Authenticate 头 |
| `SaveToken` | `bool` | — | 验证后是否存储令牌到 Properties |
| `IncludeErrorDetails` | `bool` | `true` | 是否在 WWW-Authenticate 中返回错误详情 |
| `RefreshOnIssuerKeyNotFound` | `bool` | `true` | 密钥未找到时自动刷新元数据 |
| `AutomaticRefreshInterval` | `time.Duration` | 1 天 | 元数据自动刷新间隔 |
| `RefreshInterval` | `time.Duration` | 30 秒 | 最小刷新间隔 |
| `TokenValidationParameters` | `*TokenValidationParameters` | — | 令牌验证参数 |
| `ValidateOptions` | `[]jwt.ValidateOption` | — | jwx 验证选项 |
| `SecurityTokenValidators` | `[]SecurityTokenValidator` | `[SecurityTokenHandler]` | 验证器链 |
| `BackchannelHttpHandler` | `http.RoundTripper` | — | 自定义 HTTP 传输 |
| `DPoP` | `*jwt.DPoPValidation` | nil | DPoP 校验（RFC 9449），须由 `jwt.NewDPoPValidation` 构造；nil 关闭，见下文"DPoP 校验" |

### 集成示例

```go
cfg.SetAuthenticationHandlerProvider(wicket.JwtBearerAuthenticationScheme, func(p godi.Provider) auth.Handler {
    return jwt.NewHandler(
        godi.GetRequired[optspkg.OptionsMonitor[*jwt.Options]](p),
        godi.GetRequired[*slog.Logger](p),
        godi.GetRequired[services.SystemClock](p),
    )
})
```

### 事件钩子

JWT Handler 支持事件回调（通过 `jwt.Events`）：
- `OnMessageReceived` — 令牌提取前
- `OnTokenValidated` — 验证成功后
- `OnAuthenticationFailed` — 验证失败
- `OnForbidden` — 403 响应
- `OnChallenge` — 401 质询（`Options.DPoP` 设置时质询由 DPoP 逻辑写出，不触发该事件）

### DPoP 校验（RFC 9449）

默认关闭。开启后 handler 除 `Bearer` 外还接受 `Authorization: DPoP <access token>`，要求请求带一个由 token 绑定密钥（`cnf.jkt`）签名的 `DPoP` proof，被窃取的绑定 token 无法在别处使用。

#### 启用与构造期失败

```go
v, err := jwt.NewDPoPValidation(jwt.DPoPValidationConfig{
    Options:  dpop.Options{SigningAlgorithms: []string{"ES256"}},
    Registry: registry, // 宿主注入；内存实现须显式传 replay.NewMemoryRegistry()
})
if err != nil {
    return err // 装配期失败，早于首个请求
}
opts.DPoP = v
```

- 唯一启用来源是构造函数 `jwt.NewDPoPValidation`；不读 `ServerConfig`、不经容器注册。`Options.DPoP` 为 nil 时 handler 与此前逐字节一致（不识别 `DPoP` 方案，质询仍是裸 401）。
- `DPoPValidationConfig` 字段：`Options`（`dpop.Options`，零值字段取默认；`RequireNonce` 选择 nonce 模式）、`Registry`（`replay.Registry`，必填，无内存回退）、`NonceKeys`（`dpop.NonceKeySource`）与 `Resource`（nonce 签发面标识），二者仅 nonce 模式必填、其他模式忽略；`RequestUri`（可选，见下文 htu）。
- 构造期检查，任一失败返回包装 `jwt.ErrInvalidDPoPConfiguration` 的错误、不返回对象：`Options.Validate()` 不过；`Registry` 为 nil；nonce 模式下 `NonceKeys` 为 nil、读取出错、密钥不合法（同 `dpop.ValidateNonceKeys`），或 `Resource` 为空。
- 不经构造函数得到的对象（如 `&jwt.DPoPValidation{}`）在请求期一律按不可用失败（500），不会按关闭态放行。

#### 新鲜度的两种模式

- **`iat` 模式（默认）**：proof 的 `iat` 不早于 now − `ProofLifetime` − `ClockSkew`、不晚于 now + `ClockSkew`。
- **nonce 模式（`RequireNonce: true`）**：在 `iat` 检查之外，proof 须带由本资源签发、未过期的 `nonce`。nonce 无状态、自验证，签发面为 `resource-server <Resource>`，与授权服务器的 `authorization-server <issuer>` 互不接受。缺 nonce 或 nonce 不被接受时回 `use_dpop_nonce` 质询，并在 `DPoP-Nonce` 中下发新 nonce，客户端带回重签 proof 即可。nonce 只在 401 质询中下发，成功响应不带。密钥格式、多副本共享与轮换步骤与授权服务器侧相同（见 [API 契约 · 服务端 nonce](./api-contracts.md#服务端-noncerfc-9449-8)）：新密钥先作 previous 部署到全部副本，再切为 current，旧密钥在 previous 中保留至少 `NonceLifetime` + `ClockSkew`。

#### htu 推导

proof 的 `htm` 须等于请求方法，`htu` 须指向本次请求：默认取 `scheme://Host/path`（请求经 TLS 到达时 `https`，否则 `http`；不读 `ServerUrls`），比较时 scheme 与 host 不分大小写、省略默认端口、忽略 query 与 fragment。部署在反向代理后、客户端所见 URL 与 handler 收到的不同时，设置 `RequestUri func(*http.Request) string` 返回客户端所见的 URL。它必须返回客户端所寻址的绝对 URI（`scheme://host/path`）；返回空串或相对路径时每个 proof 都会以 `invalid_dpop_proof` 被拒。

#### 校验顺序与登记

1. 识别方案：`DPoP` 方案名大小写不敏感，后跟一个或多个空格，token 非空且不含空白；`OnMessageReceived` 事件提供的 token 视为以 Bearer 出示。
2. proof 无状态校验（`(*dpop.Verifier).VerifyForResource`：签名、`typ`、`alg`、`htm`/`htu`、`iat`、`ath`），nonce 模式下再判 nonce。
3. 既有 validator 链校验 token、既有证书绑定检查（`CertificateBindingSource`）。
4. 绑定判定：`DPoP` 方案要求 token 带 `cnf.jkt` 且等于 proof 公钥指纹；绑定 token（或 `cnf` 畸形）以 Bearer 出示一律拒绝；未绑定的 Bearer token 照常通过，所带 `DPoP` 头被忽略。开启时，自定义 `SecurityTokenValidator` 产出的非内置 token 读不到 claims，按绑定失败处理。
5. 经 `Registry` 登记 proof 的 `jti`（键由 `replay.Key` 派生，限定方为 proof 公钥指纹），过期时刻取 `iat` + `ProofLifetime`、nonce 期限（nonce 模式）与 now 中较晚者再加 `ClockSkew`。同一次认证至多登记一次。

DPoP 校验与 token 校验（含证书绑定）的一切拒绝都先于登记，这些被拒请求不消耗 proof 的 `jti`；但 `OnTokenValidated` 事件在登记之后执行，被该事件拒绝（返回 error 或给出失败结果）的请求已消耗 proof 的 `jti`。核心不回收过期记录：宿主定期调用 `Registry.RemoveExpired(ctx, cutoff)`。

#### 错误与质询

认证失败以固定文本的哨兵承载（不包装底层错误文本）：`jwt.ErrDPoPProofRejected`、`jwt.ErrDPoPNonceRequired`、`jwt.ErrDPoPTokenBinding`、`jwt.ErrDPoPMalformedAuthorization`、`jwt.ErrDPoPUnavailable`。开启时 `(*jwt.Handler).HandleChallenge` 按本请求的认证结果写出质询，只有一个 `WWW-Authenticate` 头值，带 `Cache-Control: no-store`，无响应体：

| 认证结果 | 质询 |
|---|---|
| 未出示 token | 401 `DPoP algs="…"` |
| `ErrDPoPProofRejected`（proof 缺失 / 无效 / 重放、`ath` 不符） | 401 `DPoP error="invalid_dpop_proof", algs="…"` |
| `ErrDPoPNonceRequired`（nonce 缺失 / 无效 / 过期） | 401 `DPoP error="use_dpop_nonce", error_description="DPoP proof must carry the server nonce", algs="…"` + `DPoP-Nonce` |
| `ErrDPoPMalformedAuthorization` | 400 `DPoP error="invalid_request", algs="…"` |
| `ErrDPoPUnavailable`（登记端口故障、nonce 密钥源故障、非构造对象） | 500，无 `WWW-Authenticate` |
| 其余失败（`ErrDPoPTokenBinding`、证书不符、token 无效 / 过期、无可用 validator、事件给出的失败） | 401 `DPoP error="invalid_token", algs="…"` |

`algs` 为 `Options.SigningAlgorithms`（空则取默认算法列表）。nonce 模式下每个 401 质询都带新签发的 `DPoP-Nonce`，签发失败改写为 500。不可用时日志只记最内层错误的类型。质询在 handler 内调用本请求已记忆的认证结果，不会二次登记。浏览器端 JavaScript 读取 `DPoP-Nonce` 需宿主在 CORS 层暴露该头。

---

## Apple（OIDC 令牌验证）

Apple 集成通过 `oidcverify` 包实现，用于验证 Apple Sign In 签发的 ID Token。

### 提供者预设

```go
cfg := oidcverify.AppleConfig("your-apple-client-id")
// 等价于：
// ProviderConfig{
//     Issuers:   []string{"https://appleid.apple.com"},
//     JWKSURI:   "https://appleid.apple.com/auth/keys",
//     Audiences: []string{"your-apple-client-id"},
//     ClockSkew: 5 * time.Minute,
// }
```

### 使用方式

```go
verifier, err := oidcverify.NewVerifier(ctx, oidcverify.AppleConfig(clientID), clock)
if err != nil {
    // 处理初始化错误
}

// 验证 ID Token
token, err := verifier.Verify(ctx, idTokenString)
if err != nil {
    // 验证失败
}

// 带 Nonce 验证（防重放）
token, err := verifier.VerifyWithNonce(ctx, idTokenString, expectedNonce)

// 返回结果
token.Subject       // 用户唯一标识
token.Email         // 邮箱
token.EmailVerified // 邮箱是否已验证
token.Issuer        // 发行者
token.Audience      // 受众列表
```

---

## Google（OIDC 令牌验证）

同样可通过 `oidcverify` 验证 Google 签发的 ID Token：

```go
cfg := oidcverify.GoogleConfig("client-id-1", "client-id-2") // 支持多受众
// 等价于：
// ProviderConfig{
//     Issuers:   []string{"https://accounts.google.com", "accounts.google.com"},
//     JWKSURI:   "https://www.googleapis.com/oauth2/v3/certs",
//     Audiences: []string{"client-id-1", "client-id-2"},
//     ClockSkew: 5 * time.Minute,
// }
```

注意 Google 接受两种 Issuer 格式（带/不带 `https://` 前缀）。

---

## 自定义 OIDC 提供者

对于任何标准 OIDC 提供者，可直接构造 `ProviderConfig`：

```go
cfg := oidcverify.ProviderConfig{
    Issuer:    "https://your-idp.example.com",
    JWKSURI:   "https://your-idp.example.com/.well-known/jwks.json",
    Audience:  "your-client-id",
    ClockSkew: 2 * time.Minute,
}

verifier, err := oidcverify.NewVerifier(ctx, cfg, clock)
```

### ProviderConfig 字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `Issuer` | `string` | 单一发行者（与 `Issuers` 二选一） |
| `Issuers` | `[]string` | 多发行者（任一匹配即通过） |
| `JWKSURI` | `string` | JWKS 端点 URL |
| `Audience` | `string` | 单一受众（与 `Audiences` 二选一） |
| `Audiences` | `[]string` | 多受众（任一匹配即通过） |
| `ClockSkew` | `time.Duration` | 时钟偏差容忍（默认 5 分钟） |
| `NonceRequired` | `bool` | 是否强制 Nonce 验证 |

### JWKS 缓存

验证器内部使用 `jwk.Cache`，每 15 分钟自动刷新 JWKS 密钥集。

> 本地验签（`oidcverify`）与服务端交换（`wechatverify` / `phoneverify`）是两类不同机制，选用依据见下文[本地验签 vs 服务端交换](#本地验签-vs-服务端交换)。

---

## 本地验签 vs 服务端交换

wicket 提供两类「后端直调验证能力」，机制不同，适用场景也不同。两者都不参与 Web 授权码流（无 handler、无 cookie、无重定向），都由业务后端直接调用。

| 维度 | 本地验签（`oidcverify`） | 服务端交换（`wechatverify` / `phoneverify`） |
|------|------|------|
| 凭据形态 | 自包含且带签名的 ID Token | 不透明短时凭据（授权 code / 认证 token） |
| 验证方式 | 用 JWKS 公钥在本地验签 + 校验 `iss`/`aud`/`exp` | 携本方凭据向厂商发一次请求换取结果 |
| 每次验证是否出网 | 否（仅 JWKS 首取与定期刷新出网） | 是（每次验证一次往返） |
| 厂商可用性影响 | 弱：JWKS 已缓存时厂商故障不阻断验证 | 强：厂商不可用即无法验证，须 fail-closed |
| 延迟 | 微秒级（本地密码学运算） | 网络往返级 |
| 本方需持有的机密 | 无（只需公钥） | 有（应用密钥 / 访问密钥），故有脱敏要求 |
| 时钟依赖 | 有：须注入 `Clock` 校验 `exp`/`iat` | 无：时效由厂商侧判定 |
| 频率限制 | 无 | 有：受厂商 QPS 与配额约束，`ErrRetryable` 是常规分支 |
| 可离线重放校验 | 可（同一 token 可反复验证） | 不可（凭据一般一次性，重复交换即失败） |

**选用依据**：凭据是签名 JWT（Apple / Google / 标准 OIDC 提供者）→ 用 `oidcverify`，无谓的出网只会把厂商故障变成自己的故障。凭据是厂商私有的不透明串（微信授权 code、一键登录 token）→ 只能走服务端交换，因为除厂商外无人能解读它。

**两类共同的姿态**：验证失败一律 fail-closed；未配置凭据在**构造期**即失败（`ErrUnavailable`），而不是推迟到第一次验证。

---

## 后端直调验证能力 — 微信（服务端交换）

与上文的 Web 授权码流不同，本能力**不参与** scheme / cookie / challenge-callback 生命周期：它是业务后端直接调用的一个包，没有 handler、没有中间件、没有重定向。App 端拿到的授权 code 交由后端换取跨应用稳定的用户标识，appsecret 只保留在 wicket 消费方一侧，不必分发到每个业务系统。

### 基本信息

| 项 | 值 |
|------|------|
| 包路径 | `github.com/gonewx/wicket/wechatverify` |
| 端点 | `GET https://api.weixin.qq.com/sns/oauth2/access_token`（`DefaultEndpoint`） |
| 依赖 | 零第三方依赖（仅 Go 标准库：`net/http`、`net/url`、`encoding/json`、`context`、`io`、`errors` 等） |
| 接口 | `Verifier.Verify(ctx, code) (*VerifiedIdentity, error)` |

> 该端点属于**移动应用**微信登录。小程序的 `code2Session` 是另一套产品与响应形状，本能力不使用它。

### 配置选项（`wechatverify.Config`）

| 字段 | 类型 | 说明 |
|------|------|------|
| `AppID` | `string` | 移动应用标识。**必填**，缺失时 `NewVerifier` 返回 `ErrUnavailable` |
| `AppSecret` | `string` | 应用密钥。**必填**，同上 |
| `Endpoint` | `string` | 覆盖默认端点；留空取 `DefaultEndpoint` |
| `HTTPClient` | `*http.Client` | 覆盖内建客户端；留空时按 `Timeout` 构造 |
| `Timeout` | `time.Duration` | 内建客户端超时（默认 10 秒），提供 `HTTPClient` 时忽略 |

### 身份投影与降级标注

```go
type VerifiedIdentity struct {
    Subject       string        // UnionID 优先，缺失时回落 OpenID
    SubjectSource SubjectSource // "unionid" 或 "openid"
    UnionID       string        // 原始值，可能为空
    OpenID        string        // 原始值，成功时必非空
    Scope         string        // 授权 scope，原样透传
}
```

`UnionID` 仅在该应用已获得用户信息授权、且账号已绑定开放平台账号时返回，**缺失属正常场景而非错误**。此时 `Subject` 回落到 `OpenID`，`SubjectSource` 标注为 `SubjectFromOpenID`——这是一个**降级标识**：该标识只在本应用内稳定，跨应用不可用。消费方应据此决定是否接受该次登录、或引导用户完成绑定。

### 错误类别

四个 sentinel 用 `errors.Is` 判别；厂商原始返回码用 `errors.As` 取 `*VendorError` 详情。

| Sentinel | 触发条件 |
|------|------|
| `ErrInvalidCredential` | code 已使用 / 无效 / 过期、应用密钥或标识不匹配、缺少 code，**以及任何无法识别的非零返回码** |
| `ErrRetryable` | 传输失败、上游 5xx、服务繁忙、频率超限 |
| `ErrMalformedResponse` | 响应体无法解码、返回码为 0 但缺少标识、非预期的 4xx 状态 |
| `ErrUnavailable` | 未配置 `AppID` 或 `AppSecret`；`Endpoint` 形态非法；请求无法构造 |

`ErrRetryable` 另覆盖 HTTP 429 / 408——网关级限流与超时与厂商侧 45011 / -1 是同一类瞬时条件。

`context` 取消与超时**不归入上述任何类别**，而是保留原 sentinel：`ctx` 被取消时错误满足 `errors.Is(err, context.Canceled)`（此时重试与调用方的意图相悖）；deadline 到期时同时满足 `context.DeadlineExceeded` 与 `ErrRetryable`。

无法识别的返回码归入 `ErrInvalidCredential` 是**刻意的收紧默认**：把一个读不懂的响应当成可重试条件，可能把一次拒绝重试成一次意外放行。

### appsecret 不外泄

密钥随请求 query 传输，因此包内所有对外文本都经过脱敏：错误信息、`Config.String()`、验证器的 `%v` 输出中密钥一律显示为 `[REDACTED]`。脱敏同时匹配密钥的**原始形态与 query 编码形态**——传输失败返回的 `*url.Error` 内嵌的是编码后的 URL，只匹配原文会让它整条漏过。

`Config` 另实现了 `json.Marshaler` 与 `slog.LogValuer`，因此 `json.Marshal(cfg)` 与结构化日志记录 `cfg` 输出的同样是 `[REDACTED]`；反序列化方向未做改动，配置仍可从 JSON 读入。

本包**不写任何日志**。消费方在调用侧记日志时请注意：拿不到密钥的是**错误值**，而持有 `Config` 的是你自己——记录 `Config` 本身是安全的（已脱敏），但把 `AppSecret` 字段单独取出来打印不在本包的保护范围内。

**厂商错误消息（`VendorError.Msg`）同样经过脱敏后才保留**——厂商预期不会回显密钥，但该文本会到达调用方，包内所有此类路径一律脱敏而非信任。

### 集成示例

```go
verifier, err := wechatverify.NewVerifier(wechatverify.Config{
    AppID:     os.Getenv("WECHAT_APP_ID"),
    AppSecret: os.Getenv("WECHAT_APP_SECRET"),
})
if err != nil {
    // 未配置凭据：维持关闭姿态，对外返回 503
    return nil, err
}

identity, err := verifier.Verify(ctx, code)
switch {
case err == nil:
    if identity.SubjectSource == wechatverify.SubjectFromOpenID {
        // 跨应用标识不可用，按业务策略处理
    }
    return lookupOrCreateUser(identity.Subject)
case errors.Is(err, wechatverify.ErrInvalidCredential):
    return nil, status401(err)
case errors.Is(err, wechatverify.ErrRetryable):
    return nil, status503(err)
default:
    return nil, status502(err)
}
```

### DI 装配

容器只注册 `*wechatverify.Config` 作为配置扩展点，**不注册 `Verifier` 单例**——空配置构造必然失败。消费方在自己的组合根用实配置调 `NewVerifier`。

该扩展点是发给所有 scope 的**同一个共享指针**，且是**启动期扩展点**：请在容器装配阶段、任何 scope 开始服务之前写入。请求在途时写入会与每一个读取方竞争；此时把某个凭据置空，会让下一次构造转为 `ErrUnavailable`——能力被静默关闭，而链路上没有任何失败可供解释。

### 资质状态

微信开放平台真实凭据尚未申请到位，当前验证覆盖到 stub 对拍与「未配置凭据即不可用」语义；真实链路联调另行安排。

> 若你的凭据是签名 ID Token 而非授权 code，应改用[本地验签](#自定义-oidc-提供者)；两类机制的对照见[本地验签 vs 服务端交换](#本地验签-vs-服务端交换)。

---

## 后端直调验证能力 — 一键登录（号码认证服务端交换）

与微信能力同族：业务后端直调，无 handler、无中间件、无重定向。App 端经厂商移动 SDK 拿到号码认证 token，交由后端换取手机号；账号访问密钥与它驱动的请求签名集中在 wicket 一处，不必分发到每个业务系统。

### 基本信息

| 项 | 值 |
|------|------|
| 包路径 | `github.com/gonewx/wicket/phoneverify` |
| 端点 | `https://dypnsapi.aliyuncs.com`（`DefaultEndpoint`） |
| 操作 | `GetMobile`（`Version=2017-05-25`） |
| 依赖 | `github.com/aliyun/alibaba-cloud-sdk-go`（仅 `services/dypnsapi` 与 `sdk/errors`） |
| 接口 | `Verifier.Verify(ctx, token) (*VerifiedPhone, error)` |

### 配置选项（`phoneverify.PhoneAuthConfig`）

| 字段 | 类型 | 说明 |
|------|------|------|
| `AppKey` | `string` | 控制台认证方案标识。**必填**，缺失时 `NewVerifier` 返回 `ErrUnavailable` |
| `AccessKeyID` | `string` | 账号访问标识。**必填**，同上 |
| `AccessKeySecret` | `string` | 签名密钥。**必填**，同上 |
| `RegionID` | `string` | 签名所用地域；留空取 `DefaultRegionID`（`cn-hangzhou`） |
| `Endpoint` | `string` | 完整 URL 形态的端点覆盖；留空取 `DefaultEndpoint` |
| `Timeout` | `time.Duration` | 单次交换的传输层超时；≤ 0 时取默认 10 秒 |

> `AppKey` **不随请求发出**——`GetMobile` 没有该参数，它标识的是移动端 SDK 那一侧的认证方案。此处仍要求必填，是为了让「身份配置不完整」的部署被整体拒绝，而不是等到恰好被校验的那一部分才失败。

### 成功结果

```go
type VerifiedPhone struct {
    Mobile    string // 验证通过的手机号，成功时必非空
    RequestID string // 厂商请求标识，供对账与工单排查
}
```

手机号**原样透传**，本包不做任何格式转换。

### 错误类别

四个 sentinel 用 `errors.Is` 判别；厂商原始返回码、消息、请求标识与 HTTP 状态用 `errors.As` 取 `*VendorError` 详情。

| Sentinel | 触发条件 |
|------|------|
| `ErrInvalidCredential` | `isv.TOKEN_INVALID`、`isv.TOKEN_UNAUTHORIZED_USED`、`InvalidBizToken.Expired`、`InvalidBizToken.Check`、`GET_MOBILE_FAILED`，**以及任何无法识别的非 `OK` 返回码**（未识别码若随失败 HTTP 状态到达，先按状态兜底：5xx / 429 / 408 判 `ErrRetryable`，其余仍归本类） |
| `ErrRetryable` | `isp.QPS_LIMIT`、`isv.BUSINESS_LIMIT_CONTROL`、`isp.SYSTEM_ERROR`、`isp.UNKNOWN`、HTTP 5xx / 429 / 408、传输失败、SDK 超时 |
| `ErrMalformedResponse` | 响应体无法解码；返回码为 `OK` 但缺手机号 |
| `ErrUnavailable` | 未配置 `AppKey` / `AccessKeyID` / `AccessKeySecret`；`Endpoint` 形态非法；请求无法构造；**以及本方配置类厂商码**：`isv.RAM_PERMISSION_DENY`、`isv.FORBIDDEN_ACTION`、`isv.PRODUCT_UNSUBSCRIBE`、`isv.VERIFY_SCHEME_NOT_EXIST`、`SignatureDoesNotMatch`、`IncompleteSignature` |

**配置类厂商码为何归 `ErrUnavailable` 而非 `ErrInvalidCredential`**：这些码说的是「本方凭据、权限或开通状态有问题」，与「用户的 token 无效」是两回事。归入前者会让消费方对着一个完全正常的用户返回 401，把一次运维故障藏在用户身上；归入 `ErrUnavailable` 仍然 fail-closed（无人被放行），但指对了原因。此处与微信能力的分类口径不同，是因为本厂商有权威码表可精确区分。

无法识别的返回码归入 `ErrInvalidCredential` 是**刻意的收紧默认**：把一个读不懂的响应当成可重试条件，可能把一次拒绝重试成一次意外放行。唯一的放宽是未识别码**随失败 HTTP 状态到达**时：5xx / 429 / 408 说的是「厂商侧故障」而非「读不懂的拒绝」，此时按状态判 `ErrRetryable`，其余状态仍收紧。返回码采用**字符串全等**匹配，不做前缀归类——厂商的 `isv.` 前缀下同时存在凭据类与配置类两种语义，前缀归类必然把两者混为一谈。

`context` 取消与超时**不归入上述任何类别**：`ctx` 被取消时错误满足 `errors.Is(err, context.Canceled)` 且**不标可重试**（重试与调用方的意图相悖）；deadline 到期时同时满足 `context.DeadlineExceeded` 与 `ErrRetryable`。

> **`err == nil` 不等于成功**：业务失败以 HTTP 200 + 非 `OK` 返回码送达。本包判定返回码后才投影结果；消费方无需自行判断，但若自行调用厂商 SDK，这是头号陷阱。

### AccessKeySecret 不外泄

签名为 HMAC，**密钥不上网**；但签名后的请求 URL 中带有 `AccessKeyId`、**用户的 `AccessToken`** 与 `Signature`，而传输失败返回的错误内嵌完整 URL。因此包内所有对外文本都经过脱敏：**密钥、访问标识与当次 token 一并**替换为 `[REDACTED]`，且同时匹配原始形态、query 编码形态与签名回显的二次编码形态；`Signature` 与 `SignatureNonce` 的参数值逐请求变化、无法按字面匹配，按参数名剥除。脱敏一律在截断**之前**执行——先截断会把机密切成不匹配的碎片，让残留前缀漏过。

`AccessKeyID` 的口径是刻意的不对称：错误文本里它伴随签名处于可重放的 URL 语境，故剥除；配置渲染里它只是账号标识（控制台可见），保留明文供运维识别。

`PhoneAuthConfig` 实现了 `String()`（值接收者）、`GoString()`、`json.Marshaler` 与 `slog.LogValuer`，因此 `%v`/`%+v`/`%#v`、`json.Marshal(cfg)` 与结构化日志记录 `cfg` 输出的同样是 `[REDACTED]`；反序列化方向未做改动，配置仍可从 JSON 读入。

本包**不写任何日志**，并对每个 SDK client 关闭了链路追踪（SDK 在检测到进程内全局 tracer 时会以完整请求 URI 命名 span，那会绕过本包脱敏）。消费方记录 `PhoneAuthConfig` 本身是安全的（已脱敏），但把 `AccessKeySecret` 字段单独取出来打印不在本包的保护范围内；另注意 SDK 自带的 `DEBUG=sdk` 环境变量调试开关会把完整请求 URI 打到标准输出，生产环境不应设置。

### 并发与超时

`Verifier` 可被任意多个 goroutine 并发调用。厂商 SDK 的客户端在每次请求时改写自身的超时与传输层，因此本包**每次调用构造一次客户端**而不缓存共享——缓存共享客户端在 `-race` 下即报数据竞争。SDK 的 `GetMobile` 本身不接受 `context`，本包通过注入自定义传输层把调用方的 `ctx` 接进请求，使取消能真正中断在途请求。

### 集成示例

```go
verifier, err := phoneverify.NewVerifier(phoneverify.PhoneAuthConfig{
    AppKey:          os.Getenv("PHONE_AUTH_APP_KEY"),
    AccessKeyID:     os.Getenv("PHONE_AUTH_ACCESS_KEY_ID"),
    AccessKeySecret: os.Getenv("PHONE_AUTH_ACCESS_KEY_SECRET"),
})
if err != nil {
    // 未配置凭据：维持关闭姿态，对外返回 503
    return nil, err
}

phone, err := verifier.Verify(ctx, token)
switch {
case err == nil:
    return lookupOrCreateUserByPhone(phone.Mobile)
case errors.Is(err, phoneverify.ErrInvalidCredential):
    return nil, status401(err)
case errors.Is(err, phoneverify.ErrRetryable), errors.Is(err, phoneverify.ErrUnavailable):
    // 两者都是「现在无法判定」，一律不放行
    return nil, status503(err)
default:
    return nil, status502(err)
}
```

取厂商详情用于排查与工单：

```go
var vendorErr *phoneverify.VendorError
if errors.As(err, &vendorErr) {
    // vendorErr.Code / Message / RequestID / HTTPStatus 均已脱敏并限长
}
```

### DI 装配

容器只注册 `*phoneverify.PhoneAuthConfig` 作为配置扩展点（访问器 `Ptr_PhoneAuthConfig`），**不注册 `Verifier` 单例**——空配置构造必然失败。消费方在自己的组合根用实配置调 `NewVerifier`。

该扩展点是发给所有 scope 的**同一个共享指针**，且是**启动期扩展点**：请在容器装配阶段、任何 scope 开始服务之前写入。请求在途时写入会与每一个读取方竞争；此时把某个凭据置空，会让下一次构造转为 `ErrUnavailable`——能力被静默关闭，而链路上没有任何失败可供解释。

### 资质状态

厂商真实凭据尚未申请到位，当前验证覆盖到 stub 对拍与「未配置凭据即不可用」语义；真实链路联调另行安排。另有一项待核实：官方文档示例中手机号呈掩码形态，真实返回是完整号码还是掩码尚未确认——本包对此不做任何形态转换，原样透传。

> 两类机制的对照与选用依据见[本地验签 vs 服务端交换](#本地验签-vs-服务端交换)。

---

## 动态认证方案

Wicket 支持运行时注册外部提供者，无需重启服务。

### 配置

通过 `WicketOptions.DynamicProviders` 启用：

```go
opts.DynamicProviders.Enabled = true
opts.DynamicProviders.CacheTTL = 5 * time.Minute
opts.DynamicProviders.StorageProvider = myCustomStore // 可选，默认内存
```

### Provider 记录结构

```go
type Provider struct {
    Scheme      string            // 唯一方案名
    DisplayName string            // 显示名
    Enabled     bool              // 是否启用
    Protocol    string            // 协议类型
    Config      map[string]string // 协议参数（authority、client_id、scope 等）
}
```

### ProviderStore 接口

```go
type ProviderStore interface {
    GetProvider(scheme string) (*Provider, error)
    AllProviders() ([]*Provider, error)
    PutProvider(provider *Provider) error
    DeleteProvider(scheme string) error
}
```

默认实现为内存存储（`dynamicscheme.NewMemoryStore()`），生产环境可注入持久化实现。

### Resolver 缓存

`dynamicscheme.Resolver` 在 ProviderStore 之上提供 TTL 缓存层，避免每次请求都查询存储。

---

## 外部认证失败处理

当外部 IdP 认证失败时，中间件将用户重定向到配置的失败路径：

```go
cfg.SetExternalFailurePath("/account/external-failure")
```

该路径通过 `auth.Options.ExternalFailurePath` 传递到核心认证中间件。

---

## Cookie 认证方案

外部 IdP 认证成功后，Wicket 使用 Cookie 方案维持本地会话：

| Scheme | 用途 |
|--------|------|
| `wicket`（DefaultCookie） | 主会话 Cookie |
| `wicket.external`（ExternalCookie） | 外部 IdP 临时 Cookie（认证完成后清除） |

Cookie 选项通过 `authcookies.AuthenticationOptions` 配置，支持数据保护加密。

---

## 完整集成示例

```go
package main

import (
    "log/slog"
    "net/http"

    "github.com/gonewx/godi"
    "github.com/gonewx/wicket/di"
    "github.com/gonewx/wicket/server"
)

func main() {
    root := di.NewRoot()
    defer root.Close()

    cfg := godi.GetRequired[*di.ServerConfig](root)

    // 基础配置
    cfg.SetLogger(slog.Default())
    cfg.SetClients(myClients())
    cfg.SetSigningCredentialStores(mySigningKeys())

    // 外部认证失败路径
    cfg.SetExternalFailurePath("/account/external-failure")

    // 启动服务器
    srv := server.NewServer(root)
    handler := srv.UseWicket()(myAppHandler())

    http.ListenAndServe(":8080", handler)
}
```
