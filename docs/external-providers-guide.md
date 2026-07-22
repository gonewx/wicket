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
    ├── di/core.go 内置注册
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
| Scheme 名 | `Google`（`gois.GoogleAuthenticationScheme`） |
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
cfg.SetAuthenticationHandlerProvider(gois.GoogleAuthenticationScheme, func(p godi.Provider) auth.Handler {
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
| Scheme 名 | `Facebook`（`gois.FacebookAuthenticationScheme`） |
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
| Scheme 名 | `Bearer`（`gois.JwtBearerAuthenticationScheme`） |
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

### 集成示例

```go
cfg.SetAuthenticationHandlerProvider(gois.JwtBearerAuthenticationScheme, func(p godi.Provider) auth.Handler {
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
- `OnChallenge` — 401 质询

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
| `idsrv.cookie`（DefaultCookie） | 主会话 Cookie |
| `idsrv.external`（ExternalCookie） | 外部 IdP 临时 Cookie（认证完成后清除） |

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
    cfg.SetExternalFailurePath("/account/external-error")

    // 外部认证失败路径
    cfg.SetExternalFailurePath("/account/external-failure")

    // 启动服务器
    srv := server.NewServer(root)
    handler := srv.UseWicket()(myAppHandler())

    http.ListenAndServe(":8080", handler)
}
```
