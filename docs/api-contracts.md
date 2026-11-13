# Wicket API 端点

## 协议端点

Wicket 实现标准 OIDC/OAuth 2.0 协议端点，通过 `hosting.EndpointRouter` 按路径分发。路由路径常量见 `constants.go`（`ProtocolRoutePaths*`）。

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
| Revocation | `/connect/revocation` | POST | `TokenRevocationHandler` | 令牌撤销（RFC 7009） |
| End Session | `/connect/endsession` | GET/POST | `EndSessionHandler` | 登出端点 |
| End Session Callback | `/connect/endsession/callback` | GET | `EndSessionCallbackHandler` | 登出回调 |
| Check Session | `/connect/checksession` | GET | `CheckSessionHandler` | 会话状态 iframe |
| CIBA | `/connect/ciba` | POST | `BackchannelAuthenticationHandler` | 后端通道认证 |

> 常量中还定义了 `DeviceAuthorization`（`/connect/deviceauthorization`）与 mTLS 路径（`/connect/mtls/*`），但这些端点**尚未提供**：没有注册路由，discovery 也不宣告。端点注册随 handler 落地逐步启用，届时 discovery 自动恢复对应宣告。

## 支持的授权类型（Grant Types）

| Grant Type | 说明 |
|------------|------|
| `authorization_code` | 授权码流（含 PKCE） |
| `refresh_token` | 刷新令牌 |
| `client_credentials` | 客户端凭据 |
| `urn:ietf:params:oauth:grant-type:device_code` | 设备授权流：**尚未提供**。设备授权端点未注册，discovery 的 `grant_types_supported` 不宣告该类型 |
| `urn:openid:params:grant-type:ciba` | CIBA 后端通道 |
| 扩展授权 | 通过 `ExtensionGrantValidator` 接口扩展 |

> `password`（资源所有者密码）**默认不支持**：默认实现 `NotSupportedResourceOwnerPasswordValidator` 直接拒绝，宿主需注入 `ResourceOwnerPasswordValidator` 方可启用。

## 认证方案

| Scheme | 说明 |
|--------|------|
| `wicket`（DefaultCookie） | 主 Cookie 认证 |
| `wicket.external`（ExternalCookie） | 外部 IdP Cookie |
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

**按装配事实过滤**：`DiscoveryHandler` 在输出前按当前装配实际可服务的能力过滤生成的文档，不只看配置开关：

| 宣告 | 输出条件 |
|------|----------|
| `*_endpoint`、`check_session_iframe`、`jwks_uri`（位于本服务 base URL 下） | 路径已注册为端点路由（scheme 与主机不区分大小写）。指向外部主机的绝对 URL 原样保留；不是绝对 URL 的值（如未展开的 `~/` 相对路径）客户端无法解析，不输出 |
| `grant_types_supported` 中的 `device_code` | `device_authorization_endpoint` 仍在文档中 |
| `backchannel_logout_supported` / `backchannel_logout_session_supported` | `BackchannelLogoutService` 实现了 `DeliversBackChannelLogout() bool` 且返回 `true`。Back-Channel Logout 发送**尚未提供**（默认实现不发送通知），因此默认不宣告 |
| `authorization_response_iss_parameter_supported` | `EmitIssuerIdentificationResponseParameter` 为 `true` |
| `tls_client_auth` / `self_signed_tls_client_auth` | 逐个判定：该方法在已注册解析器的 `GetAvailableAuthenticationMethods()` 中 |
| `tls_client_certificate_bound_access_tokens`、`mtls_endpoint_aliases` | 至少注册了一种 tls 类客户端认证解析器。alias 条目逐条判定：对应主端点仍被宣告，且路径形态（未配置 `MutualTls.DomainName`）的 alias 路径已注册为端点路由（配置了 `DomainName` 的 domain / sub-domain 形态位于其他主机，只看主端点）；删空后整个键移除 |

令牌撤销端点已注册，`revocation_endpoint` 在默认装配下照常输出。设备授权端点（`device_authorization_endpoint`）**尚未提供**，因此不出现在文档中。`frontchannel_logout_*` 有真实实现，照常输出。宿主通过 `Discovery.CustomEntries` 添加的条目不参与过滤，但键名与生成键相同的除外。生成键指 generator 会写入文档的键，其中多数按开关写入：开关打开时 generator 丢弃同名自定义值；开关关闭时 generator 不写该键，同名自定义值会进入文档。两种情况下，这些键下的值一律按上表过滤（列表值无论是 `[]string` 还是从配置解码出的 `[]any` 都逐项判定），即使自定义值与生成值相同，或宿主在自己的路由上提供了该能力，也无法借生成键名重新宣告被撤下的能力。宿主自有的能力请用 generator 从不写入的键名宣告（例如 `registration_endpoint`），这类键只可能来自宿主，原样保留。

`MutualTls.Enabled=true` 且有任何 mTLS 相关值（上表最后两行）被移除时，每生成一次文档记一条 `slog` Warn。

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

### 令牌撤销（Revocation Endpoint，RFC 7009）

```
POST /connect/revocation
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<refresh_token_or_reference_access_token>
&token_type_hint=refresh_token
```

- 只接受 `POST`（其他方法 405）与 `application/x-www-form-urlencoded` 请求体（其他内容类型 415）。参数只从请求体读取，查询串中的 `token` 不生效。
- 端点开关 `EnableTokenRevocationEndpoint` 只控制 discovery 是否宣告 `revocation_endpoint`；与 introspection、token 端点一样，开关为 `false` 时路由照常提供服务。
- 客户端认证与令牌端点相同：经 DI 注册的 secret parser 解析凭据（默认含 `client_secret_basic`、`client_secret_post`），不要求密钥的公共客户端（`RequireClientSecret=false`）只凭 `client_id` 即可撤销自己的令牌。认证先于参数校验执行，认证失败一律返回 `{"error":"invalid_client"}`（`application/json`）：请求带 `Authorization` 头时为 **401**，并带 `WWW-Authenticate`（Basic 方案为 `Basic realm="wicket"`，其他方案回写方案名）；未带该头（凭据在请求体或缺失）时为 **400**。例外：请求体无法按表单解析时，在认证之前即返回 400 `invalid_request`。
- 认证通过后 `token` 缺失：400 `invalid_request`。请求体为空时，只有凭据放在 `Authorization` 头中才返回 400 `invalid_request`；未带该头时请求体中没有凭据，按上一条返回 400 `invalid_client`。
- `token_type_hint` 只接受 `access_token`、`refresh_token`，其他值返回 400 `unsupported_token_type`。这是对 RFC 7009 §2.2 的已知偏离（该节规定服务端忽略无效的 hint 值），为与现有请求校验器保持兼容而保留。
- 撤销 refresh token 时，同一用户、同一客户端的 reference access token 一并失效；撤销 reference access token 后，内省返回 `active=false`。注意：令牌端点目前只签发 JWT access token，没有生产路径写入 reference token store，只有宿主自行写入 store 的令牌才是 reference token。JWT access token 无服务端状态，不能撤销：提交 JWT access token 会返回 200，但不产生任何效果，该令牌在过期前仍然有效。
- 不带 `token_type_hint` 时，先按 reference access token 查找，未找到再按 refresh token 查找。带 hint 时只在该类型中查找：hint 与令牌实际类型不符时不撤销（已知限制，RFC 7009 §2.1 要求扩展到其他类型）。
- 成功响应为 200、空响应体，带 `Cache-Control: no-store` 等禁止缓存的头。未知令牌、已撤销令牌、属于其他客户端的令牌同样返回 200；属于其他客户端的令牌静默不撤销。
- 请求校验与撤销阶段的存储故障等基础设施错误不按协议错误处理，由中间件统一写出。客户端认证阶段读取客户端存储失败时，按认证失败返回 `invalid_client`。

## 存储端口（宿主实现）

存储端口分三族，宿主通过 `ServerConfig` 缝注入实现；未注入且未显式声明 `AllowInMemoryFallback()` 时装配启动失败。契约合规由 `storagetest` / `sessiontest` / `keymgmttest` 三套件校验。

### storage 族（`storage/interfaces.go`）

| 接口 | 用途 |
|------|------|
| `ClientStore` | 客户端注册查询 |
| `ResourceStore` | API/Identity 资源 |
| `AuthorizationCodeStore` | 授权码（带句柄、版本化轮换） |
| `RefreshTokenStore` | 刷新令牌（带句柄、版本化轮换） |
| `ReferenceTokenStore` | 引用令牌 |
| `PersistedGrantStore` | 持久化 grant（按 subject 批量吊销） |
| `DeviceFlowStore` | 设备流记录 |
| `BackchannelAuthenticationRequestStore` | CIBA 请求状态 |
| `UserConsentStore` | 用户同意 |
| `SigningCredentialStore` | 签名凭据 |
| `ValidationKeysStore` | 验证密钥 |
| `AuthorizationParametersMessageStore` | 授权参数跨重定向持久化 |

### session 族（`session/session.go`）

| 接口 | 用途 |
|------|------|
| `session.Store` | 服务端会话（`SessionID` 键、按 subject 批量吊销、过期清理） |

### keymgmt 族（`keymgmt/record.go`）

| 接口 | 用途 |
|------|------|
| `keymgmt.RecordStore` | 签名密钥记录（乐观并发、四阶段生命周期） |

内存实现（开发用）通过 `di/inmemory.go` 的扩展方法注册；持久化适配器接入见 [存储持久化接入指南](./storage-persistence-guide.md)。
