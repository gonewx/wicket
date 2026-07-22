# Wicket API 端点

## 协议端点

Wicket 实现标准 OIDC/OAuth 2.0 协议端点，通过 `hosting.EndpointRouter` 按路径分发。

### 端点列表

| 端点名 | 路径 | 方法 | Handler | 说明 |
|--------|------|------|---------|------|
| Authorize | `/connect/authorize` | GET/POST | `AuthorizeHandler` | 授权端点 |
| Authorize Callback | `/connect/authorize/callback` | GET/POST | `AuthorizeCallbackHandler` | 授权回调（外部 IdP 返回） |
| Token | `/connect/token` | POST | `TokenHandler` | 令牌端点 |
| Discovery | `/.well-known/openid-configuration` | GET | `DiscoveryHandler` | OIDC 发现文档 |
| Discovery JWKS | `/.well-known/openid-configuration/jwks` | GET | `DiscoveryKeyHandler` | JSON Web Key Set |
| UserInfo | `/connect/userinfo` | GET/POST | `UserInfoHandler` | 用户信息端点 |
| Introspection | `/connect/introspect` | POST | `IntrospectionHandler` | 令牌内省 |
| End Session | `/connect/endsession` | GET/POST | `EndSessionHandler` | 登出端点 |
| End Session Callback | `/connect/endsession/callback` | GET | `EndSessionCallbackHandler` | 登出回调 |
| Check Session | `/connect/checksession` | GET | `CheckSessionHandler` | 会话状态 iframe |
| CIBA | `/connect/ciba` | POST | `BackchannelAuthenticationHandler` | 后端通道认证 |

## 支持的授权类型（Grant Types）

| Grant Type | 说明 |
|------------|------|
| `authorization_code` | 授权码流（含 PKCE） |
| `refresh_token` | 刷新令牌 |
| `client_credentials` | 客户端凭据 |
| `urn:ietf:params:oauth:grant-type:device_code` | 设备授权流 |
| `urn:openid:params:grant-type:ciba` | CIBA 后端通道 |
| 扩展授权 | 通过 `ExtensionGrantValidator` 接口扩展 |

## 认证方案

| Scheme | 说明 |
|--------|------|
| `idsrv.cookie`（DefaultCookie） | 主 Cookie 认证 |
| `idsrv.external`（ExternalCookie） | 外部 IdP Cookie |
| `Google` | Google OAuth 2.0 |
| `Facebook` | Facebook OAuth 2.0 |
| `Bearer`（JWT） | JWT Bearer 令牌 |
| 动态方案 | 运行时通过 `DynamicProviderOptions` 注册 |

## Discovery 文档结构

`/.well-known/openid-configuration` 返回标准 OIDC 发现文档，包含：
- `issuer` — 发行者标识
- `authorization_endpoint` / `token_endpoint` / `userinfo_endpoint`
- `jwks_uri` — JWKS 端点
- `scopes_supported` / `response_types_supported` / `grant_types_supported`
- `token_endpoint_auth_methods_supported`
- `code_challenge_methods_supported`（S256、plain）

## 客户端认证方式

| 方式 | 实现 |
|------|------|
| `client_secret_basic` | `BasicAuthenticationSecretParser` |
| `client_secret_post` | `PostBodySecretParser` |
| `client_secret_hashed` | `HashedSharedSecretValidator` |

## 请求/响应模型

### 令牌请求（Token Endpoint）

```
POST /connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<authorization_code>
&redirect_uri=<registered_uri>
&client_id=<client_id>
&client_secret=<secret>
&code_verifier=<pkce_verifier>
```

### 令牌响应

```json
{
  "access_token": "<jwt_or_reference>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque_handle>",
  "id_token": "<jwt>"
}
```

## 存储接口（宿主实现）

宿主通过 `ServerConfig` 缝注入以下存储实现：

| 接口 | 用途 |
|------|------|
| `ClientStore` | 客户端注册查询 |
| `ResourceStore` | API/Identity 资源 |
| `PersistedGrantStore` | 授权码、刷新令牌、引用令牌 |
| `DeviceFlowStore` | 设备流记录 |
| `BackchannelAuthenticationRequestStore` | CIBA 请求状态 |
| `SigningCredentialStore` | 签名凭据 |
| `ValidationKeysStore` | 验证密钥 |
| `AuthorizationParametersMessageStore` | 授权参数跨重定向持久化 |

内存实现（开发用）通过 `di/inmemory.go` 的扩展方法注册。
