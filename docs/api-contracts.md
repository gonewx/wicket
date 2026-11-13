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
| Device Authorization | `/connect/deviceauthorization` | POST | `DeviceAuthorizationHandler` | 设备授权（RFC 8628） |
| End Session | `/connect/endsession` | GET/POST | `EndSessionHandler` | 登出端点 |
| End Session Callback | `/connect/endsession/callback` | GET | `EndSessionCallbackHandler` | 登出回调 |
| Check Session | `/connect/checksession` | GET | `CheckSessionHandler` | 会话状态 iframe |
| CIBA | `/connect/ciba` | POST | `BackchannelAuthenticationHandler` | 后端通道认证 |

**端点开关（`Endpoints.Enable*`）**：全部已注册端点的 handler 都检查各自的开关，关闭时返回 404（空响应体）；默认值均为 `true`。

| 开关 | 端点 |
|------|------|
| `EnableAuthorizeEndpoint` | Authorize 与 Authorize Callback（两条路由共用一个开关） |
| `EnableTokenEndpoint` | Token |
| `EnableIntrospectionEndpoint` | Introspection |
| `EnableBackchannelAuthenticationEndpoint` | CIBA |
| `EnableTokenRevocationEndpoint` | Revocation |
| `EnableDeviceAuthorizationEndpoint` | Device Authorization |
| `EnableDiscoveryEndpoint` | Discovery 与 Discovery JWKS |
| `EnableUserInfoEndpoint` | UserInfo |
| `EnableEndSessionEndpoint` | End Session 与 End Session Callback |
| `EnableCheckSessionEndpoint` | Check Session |

- **检查顺序有两种，并存**。Authorize、Authorize Callback、Token、Introspection、CIBA、Revocation、Device Authorization 先检查开关：关闭时对任何请求（不论方法、内容类型、凭据）都返回 404，且不读取请求。Discovery、Discovery JWKS、UserInfo、End Session、End Session Callback、Check Session 先检查请求方法：不允许的方法仍返回 405，End Session 对 POST 还先检查内容类型（415）与表单解析（400）。
- **被关闭的端点由 wicket 回答 404**，请求不会交给宿主的下一个 handler；宿主不能靠关闭开关让自己的 handler 接管同一路径。
- **开关只管自己的端点，不联动**。例如关闭 token 端点后，授权端点、设备授权端点、CIBA 端点仍可发起，但签发出的授权码、device code、`auth_req_id` 无处兑换；关闭 authorize 后，进行中的登录 / 同意流程回到 callback 时得到 404。
- **开关由经组合根装配的 handler 执行**。以 `handlers.NewAuthorizeHandler`、`handlers.NewAuthorizeCallbackHandler`、`handlers.NewTokenHandler`、`handlers.NewIntrospectionHandler`、`handlers.NewBackchannelAuthenticationHandler` 这五个既有构造函数直接构造的 handler 不持有 options、不执行开关，开关设为 `false` 时仍照常服务；需要自建的 handler 执行开关时，改用接收 options 的 `handlers.NewAuthorizeHandlerWithOptions`、`handlers.NewAuthorizeCallbackHandlerWithOptions`、`handlers.NewTokenHandlerWithOptions`、`handlers.NewIntrospectionHandlerWithOptions`、`handlers.NewBackchannelAuthenticationHandlerWithOptions`。
- 开关关闭时 discovery 文档的变化见下文"Discovery 文档结构"一节"按装配事实过滤"的说明。

> 常量中还定义了 mTLS 路径（`/connect/mtls/*`），但这些端点**尚未提供**：没有注册路由，discovery 也不宣告。端点注册随 handler 落地逐步启用，届时 discovery 自动恢复对应宣告。

## 支持的授权类型（Grant Types）

| Grant Type | 说明 |
|------------|------|
| `authorization_code` | 授权码流（含 PKCE） |
| `refresh_token` | 刷新令牌 |
| `client_credentials` | 客户端凭据 |
| `urn:ietf:params:oauth:grant-type:device_code` | 设备授权流（RFC 8628），设备码先经设备授权端点获取，见下文"设备授权" |
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
| `backchannel_logout_supported` / `backchannel_logout_session_supported` | `BackchannelLogoutService` 实现了 `DeliversBackChannelLogout() bool` 且返回 `true`。默认实现在 `ServerSideSessions.Enabled` 与 `Endpoints.EnableCheckSessionEndpoint` 同时为 `true` 时返回 `true`；默认装配不开启 server-side sessions，因此默认不宣告（另受 generator 既有条件 `EnableEndSessionEndpoint` 约束）。见下文"Back-Channel Logout 发送" |
| `authorization_response_iss_parameter_supported` | `EmitIssuerIdentificationResponseParameter` 为 `true` |
| `tls_client_auth` / `self_signed_tls_client_auth` | 逐个判定：该方法在已注册解析器的 `GetAvailableAuthenticationMethods()` 中 |
| `tls_client_certificate_bound_access_tokens`、`mtls_endpoint_aliases` | 至少注册了一种 tls 类客户端认证解析器。alias 条目逐条判定：对应主端点仍被宣告，且路径形态（未配置 `MutualTls.DomainName`）的 alias 路径已注册为端点路由（配置了 `DomainName` 的 domain / sub-domain 形态位于其他主机，只看主端点）；删空后整个键移除 |

令牌撤销端点与设备授权端点已注册，`revocation_endpoint`、`device_authorization_endpoint` 以及 `grant_types_supported` 中的 `device_code` 在默认装配下照常输出；`EnableDeviceAuthorizationEndpoint=false` 时后两者不输出；`EnableTokenRevocationEndpoint=false` 时 generator 不输出 `revocation_endpoint`，宿主未配置同名自定义条目时文档中没有该键。授权、令牌、内省、CIBA 四个端点的开关同理，关闭时 generator 不输出下列键，宿主未配置同名自定义条目时文档中没有这些键：`EnableAuthorizeEndpoint=false` 时为 `authorization_endpoint`、`request_parameter_supported`、`request_object_signing_alg_values_supported`，以及 `EnableJwtRequestUri=true` 时才有的 `request_uri_parameter_supported`；`EnableTokenEndpoint=false` 时为 `token_endpoint`；`EnableIntrospectionEndpoint=false` 时为 `introspection_endpoint`；`EnableBackchannelAuthenticationEndpoint=false` 时为 `backchannel_authentication_endpoint`、`backchannel_token_delivery_modes_supported`、`backchannel_user_code_parameter_supported`，以及 `grant_types_supported` 中的 `urn:openid:params:grant-type:ciba`。authorize 或 token 端点关闭后，`response_types_supported`、`response_modes_supported`、`grant_types_supported`、`token_endpoint_auth_methods_supported` 等仍照常输出。`frontchannel_logout_*` 照常输出（不开启 server-side sessions 时 front-channel 通知不会发生，见下文 Back-Channel Logout 的已知限制）。宿主通过 `Discovery.CustomEntries` 添加的条目不参与过滤，但键名与生成键相同的除外。生成键指 generator 会写入文档的键，其中多数按开关写入：开关打开时 generator 丢弃同名自定义值；开关关闭时 generator 不写该键，同名自定义值会进入文档。两种情况下，这些键下的值一律按上表过滤（列表值无论是 `[]string` 还是从配置解码出的 `[]any` 都逐项判定）。上表按装配事实判定，端点开关不是过滤条件。被过滤撤下的能力，宿主无法借生成键名重新宣告：就端点而言，路径未注册为端点路由时，同名自定义值若指向本服务 base URL 下的该路径（包括宿主在 wicket 端点路由之外自行提供的路径），或不是绝对 URL，照样被撤下，即使自定义值与生成值相同。开关关闭而路由仍已注册时则不被撤下：`EnableTokenRevocationEndpoint=false` 时 generator 不写入 `revocation_endpoint`，端点对任何请求返回 404；宿主此时若以同名自定义条目写入指向本服务撤销路由的值，或任何外部绝对 URL，该值会出现在 discovery 文档中。其中指回本服务撤销路由的情形是已知限制：文档宣告了一个返回 404 的端点，开关关闭时，宿主不应以该键指回本服务的撤销路由。同一已知限制也适用于 `authorization_endpoint`、`token_endpoint`、`introspection_endpoint`、`backchannel_authentication_endpoint`：对应开关关闭而宿主以同名自定义条目指回本服务的对应路由时，条目仍出现在文档中，而该端点返回 404；开关关闭时，宿主不应以这些键指回本服务路由。`request_parameter_supported`、`request_object_signing_alg_values_supported`（authorize 关闭时）与 `backchannel_token_delivery_modes_supported`、`backchannel_user_code_parameter_supported`（CIBA 关闭时）的同名自定义值同样会进入文档。宿主自有的能力请用 generator 从不写入的键名宣告（例如 `registration_endpoint`），这类键只可能来自宿主，原样保留。

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

- `EnableTokenEndpoint=false` 时，端点对任何请求都返回 404，discovery 不宣告 `token_endpoint`（generator 不写入该键；宿主以同名自定义条目写入的情形见上文"Discovery 文档结构"一节"按装配事实过滤"的说明）。默认为 `true`。开关的检查顺序、不联动与直接构造 handler 的情形见上文"端点列表"之后关于端点开关的说明。

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

- `access_token` 的形态由 client 的 `AccessTokenType` 决定，取值为 `wicket.AccessTokenTypeJwt`（默认）或 `wicket.AccessTokenTypeReference`。取 Jwt 时是自包含的 JWT；取 Reference 时是由 64 个大写十六进制字符组成的不透明句柄（不含 `.`），令牌本身写入 `ReferenceTokenStore`。两种形态下 `token_type`、`expires_in`、`scope`、`refresh_token` 的规则相同，`id_token` 恒为 JWT。授权端点在 `response_type` 含 `token` 时签发的 access token 同样随该配置为句柄。
- 句柄可经内省查询（有效时 `active=true`）、可用于 userinfo、可由所属 client 在撤销端点立即撤销；撤销 refresh token 时，同一用户、同一 client 的全部句柄一并失效（范围按用户与 client 计，含该用户在同一 client 下其他登录取得的句柄）。refresh 换发每次签发新句柄，不撤销此前签发的句柄。资源侧不能在本地验证句柄，须改用内省；`auth/jwt` 的 bearer 认证方案只接受 JWT，不接受句柄。
- refresh 换发默认复用随 refresh token 保存的 access token 模型，形态取自该 refresh token 签发时的 client 配置。因此升级到本版本之前、或 client 改为 Reference 之前签发的 refresh token，在整条 refresh 链上持续换得 JWT（不可撤销），直到用户重新登录；可撤销这些 refresh token 或等其过期，也可对该 client 开启 `UpdateAccessTokenClaimsOnRefresh`，使每次换发按当前配置重新装配。两种做法都不追溯已签发的 JWT。client 改回 Jwt 时同理，已入库的句柄在过期或被撤销前继续有效。
- 签发句柄时 `ReferenceTokenStore` 写入失败则不签发任何令牌（不退回 JWT），端点按基础设施错误返回非 200 与固定文本；store 的错误文本不进入响应与 wicket 日志，wicket 只记录 client id、故障分类与错误类型，具体原因须由宿主的 store 自行记录（其错误文本与日志不应包含句柄或记录内容）。access token 入库后同一请求的后续步骤失败时，已入库的记录不回滚，其句柄从未交出。

### 令牌撤销（Revocation Endpoint，RFC 7009）

```
POST /connect/revocation
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<refresh_token_or_reference_access_token>
&token_type_hint=refresh_token
```

- `EnableTokenRevocationEndpoint=false` 时，端点对任何请求都返回 404，discovery 不宣告 `revocation_endpoint`（generator 不写入该键；宿主以同名自定义条目写入的情形见上文"Discovery 文档结构"一节"按装配事实过滤"的说明）。默认为 `true`。以下各条均以开关打开为前提。
- 只接受 `POST`（其他方法 405）与 `application/x-www-form-urlencoded` 请求体（其他内容类型 415）。参数只从请求体读取，查询串中的 `token` 不生效。
- 客户端认证与令牌端点相同：经 DI 注册的 secret parser 解析凭据（默认含 `client_secret_basic`、`client_secret_post`），不要求密钥的公共客户端（`RequireClientSecret=false`）只凭 `client_id` 即可撤销自己的令牌。认证先于参数校验执行，认证失败一律返回 `{"error":"invalid_client"}`（`application/json`）：请求带 `Authorization` 头时为 **401**，并带 `WWW-Authenticate`（Basic 方案为 `Basic realm="wicket"`，其他方案回写方案名）；未带该头（凭据在请求体或缺失）时为 **400**。例外：请求体无法按表单解析时，在认证之前即返回 400 `invalid_request`。
- 认证通过后 `token` 缺失：400 `invalid_request`。请求体为空时，只有凭据放在 `Authorization` 头中才返回 400 `invalid_request`；未带该头时请求体中没有凭据，按上一条返回 400 `invalid_client`。
- `token_type_hint` 只接受 `access_token`、`refresh_token`，其他值返回 400 `unsupported_token_type`。这是对 RFC 7009 §2.2 的已知偏离（该节规定服务端忽略无效的 hint 值），为与现有请求校验器保持兼容而保留。`unsupported_token_type` 还有第二个来源：JWT 形态的令牌，见下条。
- 撤销 refresh token 时，同一用户、同一客户端的 reference access token 一并失效；撤销 reference access token 后，内省返回 `active=false`。reference access token 指配置了 `AccessTokenType=Reference` 的 client 取得的句柄（见上文"令牌响应"），以及宿主自行写入 store 的令牌；默认形态的 client 取得的是 JWT。JWT access token 无服务端状态，不能撤销：提交 JWT 形态的令牌返回 400 `unsupported_token_type`，不触碰任何令牌 store，该令牌在过期前仍然有效。判定方式：令牌字符串含 `.` 即视为 JWT 形态，与 access token 校验区分 JWT 与 reference 句柄的规则相同；不验证签名，不看 `token_type_hint`；因此其他客户端的、已过期的、伪造的含 `.` 字符串同样得到 400。对无效、伪造、过期的含 `.` 字符串返回 400，是对 RFC 7009 §2.2 的已知偏离（该节规定客户端提交无效令牌时返回 200），范围仅限含 `.` 的字符串。由此带来一条限制：句柄不得含 `.`。宿主自行写入 store 的 refresh 或 reference 句柄若含 `.`，在撤销端点得到 400，无法经此端点撤销；默认装配生成的句柄不含 `.`，不受影响。
- 以下查找规则只适用于不含 `.` 的令牌。不带 `token_type_hint` 时，先按 reference access token 查找，未找到再按 refresh token 查找。带 hint 时只在该类型中查找：hint 与令牌实际类型不符时不撤销（已知限制，RFC 7009 §2.1 要求扩展到其他类型）。
- 成功响应为 200、空响应体，带 `Cache-Control: no-store` 等禁止缓存的头。不含 `.` 的未知令牌、已撤销令牌、属于其他客户端的令牌同样返回 200；属于其他客户端的令牌静默不撤销。
- 请求校验与撤销阶段的存储故障等基础设施错误不按协议错误处理，由中间件统一写出。客户端认证阶段读取客户端存储失败时，按认证失败返回 `invalid_client`。

### 设备授权（Device Authorization Endpoint，RFC 8628）

```
POST /connect/deviceauthorization
Content-Type: application/x-www-form-urlencoded

client_id=<client_id>
&client_secret=<secret>
&scope=openid%20api1%20offline_access
```

- `EnableDeviceAuthorizationEndpoint=false` 时，端点对任何请求都返回 404，discovery 不宣告 `device_authorization_endpoint`，`grant_types_supported` 也不含 `device_code`。默认为 `true`。关闭开关前已签发的 device code 在过期前仍可在令牌端点兑换，前提是令牌端点的开关（`EnableTokenEndpoint`）打开；令牌端点关闭时无处兑换。
- 只接受 `POST`（其他方法 405）与 `application/x-www-form-urlencoded` 请求体（其他内容类型 415）。参数只从请求体读取，查询串不生效；请求体无法按表单解析时返回 400 `invalid_request`。
- 客户端认证与令牌端点相同：经 DI 注册的 secret parser 解析凭据（默认含 `client_secret_basic`、`client_secret_post`），不要求密钥的公共客户端（`RequireClientSecret=false`）只需在请求体中带 `client_id`。认证失败返回 `{"error":"invalid_client"}`：请求带 `Authorization` 头时为 **401** 并带 `WWW-Authenticate`，否则为 **400**，与撤销端点一致。
- 客户端不允许 device_code 授权类型时返回 400 `unauthorized_client`；scope 无效、身份 scope 缺少 `openid`，或未传 `scope` 且客户端没有 `AllowedScopes` 时返回 400 `invalid_scope`；`scope` 超长返回 400 `invalid_request`。这些错误的响应体只含 `error`，`Content-Type: application/json`，并带禁止缓存的头。未传 `scope` 时默认取客户端全部 `AllowedScopes`（`AllowOfflineAccess=true` 时追加 `offline_access`）。
- 成功响应为 200、`application/json`、禁止缓存：

```json
{
  "device_code": "<opaque_handle>",
  "user_code": "<9 位数字>",
  "verification_uri": "https://<server>/device",
  "verification_uri_complete": "https://<server>/device?userCode=<user_code>",
  "expires_in": 300,
  "interval": 5
}
```

  `expires_in` 取客户端的 `DeviceCodeLifetime`，`interval` 取 `DeviceFlow.Interval`（默认 5）。`verification_uri` 取 `UserInteraction.DeviceVerificationUrl`（相对路径时拼上服务器 base URL）；`DeviceVerificationUserCodeParameter` 为空时不输出 `verification_uri_complete`。
- 设备随后在令牌端点轮询：

```
POST /connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=<device_code>
&client_id=<client_id>
&client_secret=<secret>
```

  用户尚未处理时返回 400 `authorization_pending`；同一 device_code 在轮询间隔内再次轮询返回 `slow_down`（间隔取客户端的 `PollingInterval`，未设时取 `DeviceFlow.Interval`）；用户拒绝后返回 `access_denied`；过期后返回 `expired_token`；未知或属于其他客户端的 device_code 返回 `invalid_grant`。用户批准后返回令牌，`scope` 为用户批准的 scope；批准范围含 `offline_access` 时同时签发 refresh token，用它刷新得到的 scope 不超出批准范围。兑换成功后记录即删除，再次兑换返回 `invalid_grant`。令牌端点先判定轮询间隔，再判定过期与拒绝：在间隔内再次轮询已过期或已拒绝的 device code 时，返回 `slow_down` 而不是 `expired_token` 或 `access_denied`。
- 请求校验与生成阶段的存储故障等基础设施错误不按协议错误处理，由中间件统一写出。

#### 宿主验证页面：`services.DeviceFlowInteractionService`

wicket 不带验证页面。宿主在自己的验证页面（默认路径 `/device`，查询参数 `userCode` 携带 user code）中，从请求作用域解析交互服务，方式与 `services.InteractionService` 相同：

```go
interaction := godi.GetRequired[services.DeviceFlowInteractionService](hosting.ScopeFrom(r.Context()))

authz, err := interaction.GetAuthorizationContext(ctx, userCode)
// authz.ClientId / ClientName / RequestedScopes / IsOpenIdRequest / Expiration

err = interaction.Approve(ctx, userCode, user, sessionId, []string{"openid", "api1"})
// 或
err = interaction.Deny(ctx, userCode)
```

- 三个方法按以下顺序判定，先命中者返回：store 读取失败（包装后返回）→ `ErrDeviceFlowUserCodeNotFound`（user code 不存在，或其客户端已不存在、已停用）→ `ErrDeviceFlowUserCodeExpired` → `ErrDeviceFlowUserCodeAlreadyHandled`（每个 user code 只能批准或拒绝一次）。
- `Approve` 另返回 `ErrDeviceFlowInvalidApproval`：主体为 nil 或没有 `sub`；scope 为空；含有未请求的 scope；OpenID Connect 请求的批准范围不含 `openid`。批准范围去重后写入，并同时作为该授权的请求范围，因此 refresh token 不会放宽回原请求。
- 传入的主体应为已认证用户：`sub` 必需，建议同时带 `auth_time`、`idp`、`amr`。主体的 claim 原样进入 access token 与 id_token。`sessionId` 可以为空。
- 不提供"记住同意"：交互服务不读写同意存储，每次设备授权都须用户在页面上明确批准。按 RFC 8628 §5.4，页面应告知用户正在授权一台设备，并显示 `ClientName` 等设备相关信息。
- 写入失败（含 store 报告记录不存在）以包装后的错误返回，不映射为上述哨兵错误。

#### 已知限制

- 宣告的 `interval` 取 `DeviceFlow.Interval`，而节流优先取客户端的 `PollingInterval`，两者可能不一致。
- user code 默认为 9 位数字，由 `math/rand` 生成；wicket 不对 user code 的尝试次数限速（RFC 8628 §5.1），限速由宿主验证页面负责。
- `verification_uri_complete` 中的 user code 未做 URL 编码。
- 拒绝后的记录不会立即删除，在过期前每次轮询都返回 `access_denied`。
- 令牌端点按 device_code 查找记录与删除记录不是原子操作，并发轮询可能重复兑换；交互服务的读取—写回同样不是原子操作。
- 默认的 refresh token 服务不校验 refresh token 的客户端绑定与有效期，设备流签发的 refresh token 同样受影响。
- 令牌响应对所有授权类型都写出 `refresh_token` 成员，未签发时为空字符串。

### Back-Channel Logout 发送（OIDC Back-Channel Logout 1.0）

**启用条件**：`ServerSideSessions.Enabled=true` 且 `Endpoints.EnableCheckSessionEndpoint=true`（后者默认开启）。只有这时 wicket 才跨请求记住会话与其登录过的客户端，ID Token 才带 `sid`。条件不满足时 discovery 不宣告，服务也不发送任何通知。

**宿主要求**：
- 登录时经 `services.UserSession.CreateSessionId` 建立会话（集成测试宿主的 cookie 认证处理器在 `SignIn` 中这样做）。之后的请求中，wicket 按会话 cookie 从会话存储恢复会话，但只在当前请求的已认证主体（缺省认证方案）与会话记录的 subject 相同时才采用；否则按无会话处理并清除会话 cookie。
- 对缺省登出方案（`scheme` 为空或等于 `GetDefaultSignOutScheme()`）调用 `SignOut` 会同时清除会话 cookie；对其他方案（如外部登录的临时方案）的 `SignOut` 不影响会话。
- 宿主登出页经 `InteractionService.GetLogoutContext` 取得 `SignOutIFrameUrl` 并渲染为 iframe。
- 经 `ServerConfig.SetBackChannelLogoutHttpClient` 注入的 HTTP client **必须设置超时**：投递所用的 client 不关闭响应体，连接回收依赖超时。未注入时使用缺省 client：5 秒超时，不跟随重定向（避免 logout token 被转发到预注册地址之外）。注入的 client 原样使用，重定向策略由宿主负责：Go 的 `http.Client` 默认跟随重定向，遇到 307 / 308 会把表单（含 logout token）重发到新地址，建议同样设置 `CheckRedirect` 返回 `http.ErrUseLastResponse`。

**触发点**：浏览器加载 `/connect/endsession/callback?endSessionId=…`（即上述 iframe）且回调校验通过时，按同一句柄读取登出上下文并投递，然后照常渲染 front-channel 页面。校验失败（400）不投递。上下文写入超过 300 秒后（按注入的 `SystemClock` 判定）再加载回调不再投递。

**投递前核对**：上下文须指向会话存储中存在且未过期的会话；上下文若带 subject，须与会话记录一致；只通知同时出现在上下文与会话记录中的客户端。不满足时整轮不发送，记 Warn；会话存储读取失败时同样整轮不发送，Warn 中带存储错误。

**logout token**：
- JOSE 头 `typ=logout+jwt`，用当前签名凭证签名，算法规则同该客户端的 ID Token（`AllowedIdentityTokenSigningAlgorithms`）。
- claims 只含 `iss`（当前 issuer；登出上下文中携带的 issuer 不被采用）、`aud`（client_id，序列化为单元素数组，RFC 7519 下与字符串等价）、`iat`、`nbf`、`exp`（`iat`+120 秒）、`jti`（每个 token 新生成）、`events`（`{"http://schemas.openid.net/event/backchannel-logout":{}}`）、`sid`（会话标识）与 `sub`（会话记录的 subject）；不含 `nonce`。
- 跳过并记 Warn 的情形：`BackChannelLogoutUri` 不是绝对 http(s) URI 或含 fragment；`sub` 与 `sid` 都没有；客户端要求 `BackChannelLogoutSessionRequired` 但没有 `sid`；签发前再次查询时客户端已停用或查不到；签发失败。已停用或不存在的客户端通常在生成通知列表时就被排除，这一步不记日志。

**发送**：对每个客户端以 `application/x-www-form-urlencoded` POST `logout_token=…`，并发进行，回调最多等待 5 秒；不重发。单个 RP 失败（连接错误、非 200 响应等）只记日志，不影响其他 RP，也不影响回调页面。日志不含 logout token。

**ID Token `sid`**：会话内签发的 ID Token 带 `sid`，与 logout token 的 `sid` 相同，匿名请求不带。

**已知限制**：
- 投递依赖宿主渲染回调 iframe 且浏览器加载它；宿主不渲染或浏览器未加载时不发送。
- 回调地址在上下文写入后 300 秒内重复加载会重复投递（每次 `jti` 不同）。
- 不经 `/connect/endsession`、由宿主直接清除 cookie 的登出不产生登出上下文，不发送。
- server-side session 过期或被管理面删除时不发送。
- 登出上下文句柄由默认数据保护实现编码，不具加密与完整性保护；投递前的会话核对只能挡住指向未知会话的伪造，知道某个会话 `sid` 的一方（如该会话的 RP）可以伪造上下文，让该会话的所有 RP 收到登出通知。
- HTTP client 把非 200 响应（包括规范视为成功的 204）记为 Warn，成功响应也以 Error 级记录。
- 不对 `BackChannelLogoutUri` 做内网地址过滤。
- 默认装配下 `frontchannel_logout_supported` / `frontchannel_logout_session_supported` 照常宣告，但不开启 server-side sessions 时 front-channel 通知同样不会发生。
- 宿主登录未经 `CreateSessionId` 时不建立会话，也就不会投递。

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
