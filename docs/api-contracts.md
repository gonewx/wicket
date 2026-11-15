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
| Authorization Server Metadata | `/.well-known/oauth-authorization-server`（issuer 含路径时其后接该路径） | GET | `AuthorizationServerMetadataHandler` | OAuth 2.0 授权服务器元数据（RFC 8414），见下文「授权服务器元数据（RFC 8414）」 |
| UserInfo | `/connect/userinfo` | GET/POST | `UserInfoHandler` | 用户信息端点 |
| Introspection | `/connect/introspect` | POST | `IntrospectionHandler` | 令牌内省（RFC 7662）；`Accept` 请求 `application/token-introspection+jwt` 时返回签名 JWT（RFC 9701），见下文「JWT 形式的内省响应（RFC 9701）」 |
| Revocation | `/connect/revocation` | POST | `TokenRevocationHandler` | 令牌撤销（RFC 7009） |
| Device Authorization | `/connect/deviceauthorization` | POST | `DeviceAuthorizationHandler` | 设备授权（RFC 8628） |
| End Session | `/connect/endsession` | GET/POST | `EndSessionHandler` | 登出端点 |
| End Session Callback | `/connect/endsession/callback` | GET | `EndSessionCallbackHandler` | 登出回调 |
| Check Session | `/connect/checksession` | GET | `CheckSessionHandler` | 会话状态 iframe |
| CIBA | `/connect/ciba` | POST | `BackchannelAuthenticationHandler` | 后端通道认证 |
| Pushed Authorization Request | `/connect/pushedauthorization` | POST | `PushedAuthorizationRequestHandler` | 推送授权请求（RFC 9126），仅在 `EnablePushedAuthorizationRequests` 后路由，见下文「推送授权请求（PAR）」 |

**端点开关（`Endpoints.Enable*`）**：全部已注册端点的 handler 都检查各自的开关，关闭时返回 404（空响应体）；默认值均为 `true`。

| 开关 | 端点 |
|------|------|
| `EnableAuthorizeEndpoint` | Authorize 与 Authorize Callback（两条路由共用一个开关） |
| `EnableTokenEndpoint` | Token |
| `EnableIntrospectionEndpoint` | Introspection |
| `EnableBackchannelAuthenticationEndpoint` | CIBA |
| `EnableTokenRevocationEndpoint` | Revocation |
| `EnableDeviceAuthorizationEndpoint` | Device Authorization |
| `EnableDiscoveryEndpoint` | Discovery、Discovery JWKS 与 Authorization Server Metadata |
| `EnableUserInfoEndpoint` | UserInfo |
| `EnableEndSessionEndpoint` | End Session 与 End Session Callback |
| `EnableCheckSessionEndpoint` | Check Session |

- **检查顺序有两种，并存**。Authorize、Authorize Callback、Token、Introspection、CIBA、Revocation、Device Authorization 先检查开关：关闭时对任何请求（不论方法、内容类型、凭据）都返回 404，且不读取请求。Discovery、Discovery JWKS、UserInfo、End Session、End Session Callback、Check Session 先检查请求方法：不允许的方法仍返回 405，End Session 对 POST 还先检查内容类型（415）与表单解析（400）。
- **被关闭的端点由 wicket 回答 404**，请求不会交给宿主的下一个 handler；宿主不能靠关闭开关让自己的 handler 接管同一路径。
- **开关只管自己的端点，不联动**。例如关闭 token 端点后，授权端点、设备授权端点、CIBA 端点仍可发起，但签发出的授权码、device code、`auth_req_id` 无处兑换；关闭 authorize 后，进行中的登录 / 同意流程回到 callback 时得到 404。
- **开关由经组合根装配的 handler 执行**。以 `handlers.NewAuthorizeHandler`、`handlers.NewAuthorizeCallbackHandler`、`handlers.NewTokenHandler`、`handlers.NewIntrospectionHandler`、`handlers.NewBackchannelAuthenticationHandler` 这五个既有构造函数直接构造的 handler 不持有 options、不执行开关，开关设为 `false` 时仍照常服务；需要自建的 handler 执行开关时，改用接收 options 的 `handlers.NewAuthorizeHandlerWithOptions`、`handlers.NewAuthorizeCallbackHandlerWithOptions`、`handlers.NewTokenHandlerWithOptions`、`handlers.NewIntrospectionHandlerWithOptions`、`handlers.NewBackchannelAuthenticationHandlerWithOptions`。
- 开关关闭时 discovery 文档的变化见下文"Discovery 文档结构"一节"按装配事实过滤"的说明。

> 常量中还定义了 mTLS 路径（`/connect/mtls/*`），但这些端点**尚未提供**：没有注册路由，discovery 也不宣告。端点注册随 handler 落地逐步启用，届时 discovery 自动恢复对应宣告。

PAR 端点不受 `Endpoints.Enable*` 控制（`EndpointsOptions` 没有它的开关）：唯一开关是 `ServerConfig.EnablePushedAuthorizationRequests`。未启用时 `/connect/pushedauthorization` 与 mTLS 别名 `/connect/mtls/pushedauthorization` 的路由不产出 handler，请求落到宿主的下一个 handler（通常 404）；mTLS 别名另需 `EnableClientCertificateAuthentication`。

## 推送授权请求（PAR）

RP 先从后端把授权参数推送给 PAR 端点，换得不透明的 `request_uri`，浏览器只带 `client_id` 与 `request_uri` 访问 authorize（RFC 9126）。默认关闭。

### 启用

```go
cfg := root.ServerConfig()
cfg.SetPushedAuthorizationRequestStore(memory.NewMemoryPushedAuthorizationRequestStore())
cfg.SetPushedAuthorizationDataProtectionProvider(hostProvider) // 不得为默认实现
cfg.EnablePushedAuthorizationRequests(pushedauth.Options{RequestUriLifetime: 90 * time.Second})
cfg.Freeze()
```

`EnablePushedAuthorizationRequests` 在 `Freeze()` 之后调用、或任一时长为负时 panic；`PushedAuthorizationRequestsEnabled()` 查询，`PushedAuthorizationRequestsOptions()` 返回补齐默认值后的选项。启用后两条 PAR 缝为特性条件必需（见[存储持久化接入指南](./storage-persistence-guide.md#注入-par-存储与-par-数据保护)）。

| `pushedauth.Options` 字段 | 默认 | 含义 |
|------|------|------|
| `RequestUriLifetime` | 60s | 入口有效期，即推送响应的 `expires_in`；首次访问 authorize 时判定 |
| `InteractionGracePeriod` | 10min | 交互往返宽限：入口有效期内进入 authorize 的请求，登录 / 同意往返可延续到 入口有效期 + 宽限 |
| `RequireForAllClients` | false | 全局强制 PAR：所有 client 只能经 PAR `request_uri` 访问 authorize；discovery 宣告 `require_pushed_authorization_requests: true` |
| `Clock` | 容器的 `services.SystemClock` | 判定时限用的时钟 |

零值时长取默认值。

client 元数据（`models.ClientPushedAuthorizationMetadata`，嵌入 `models.Client`）：

| 字段 | 含义 |
|------|------|
| `RequirePushedAuthorizationRequests` | 该 client 只能经 PAR 访问 authorize（RFC 9126 §6）。PAR 未启用时该 client 配置无效：`FindClientById` 返回 `storage.ErrInvalidClientConfiguration` |
| `RequestUriLifetime` | 该 client 的入口有效期（秒），大于 0 时取代全局值；0 用全局值；负值为配置无效 |

### 端点契约

`POST /connect/pushedauthorization`，`application/x-www-form-urlencoded`，参数只读请求体。

1. 非 POST → 405；非表单 → 415。
2. 客户端认证与撤销端点同一组合（client secret、`private_key_jwt`、mTLS）。认证基础设施不可用 → 500 固定体；认证失败 → `invalid_client`（带 `Authorization` 头时 401，否则 400）。
3. 请求体的 `client_id` 与已认证 client 不一致（或出现多个）→ 400 `invalid_request`；缺省时补入。剔除 `client_secret`、`client_assertion`、`client_assertion_type`。
4. 按 authorize 同等规则校验（`Push` 阶段，含 redirect_uri 预注册、scope、PKCE、`request` 对象）；`request_uri` 出现即 `invalid_request`。失败 → 400 `{"error","error_description"}`（描述为空时省略 `error_description`）；基础设施失败 → 500。
5. 成功 → **201**，`Content-Type: application/json`，`Cache-Control: no-cache, no-store`：

```json
{"request_uri": "urn:ietf:params:oauth:request_uri:…", "expires_in": 60}
```

存储的是剔除认证参数后的原始表单（不是合并 `request` 对象后的结果），载荷经 PAR 数据保护缝保护。

### authorize 端的解析

- `request_uri` 以 `urn:ietf:params:oauth:request_uri:` 开头即按 PAR 句柄解析，**不会**进入 `request_uri` 远程抓取；PAR 未启用时直接 `invalid_request_uri`。
- 记录缺失、属于其他 client、时限已过或载荷无法还原 → `invalid_request_uri`，记录不消费；存储故障 → `server_error`。
- 解析成功后，推送的参数作为工作集参与全部后续校验；外层 URL 上的其他参数被忽略。校验后的请求在 `PushedRequestUri` / `PushedParameters`（`validators/models.PushedAuthorizationRequestValues`）中携带展开结果，`Raw`、登录 / 同意的 returnUrl 与 `AuthorizationParametersMessageStore` 中只有 `client_id`、`request_uri`、`par_entry_receipt`（以及 wicket 内部的 `suppressed_prompt`）。因此交互页经 `GetAuthorizationContext` 取得的 `messages.AuthorizationRequest.Parameters` 也只有这组最小参数，不含推送的授权参数；交互页应读取 `AuthorizationRequest` 的类型化字段（`Client`、`RedirectUri`、`PromptModes`、`ValidatedResources` 等），需要原始推送参数的宿主代码改读校验后请求的 `PushedParameters`。
- **两种时限与进入回执。** 首次进入按入口有效期判定，通过后签发 `par_entry_receipt`（PAR 保护器保护的回执，绑定 `request_uri` 与进入时间）随 returnUrl 往返；callback 与 `OidcReturnUrlParser` 只有带有效回执时才按保留期判定，无回执或回执无效一律按首次进入判定，所以直接访问 callback 绕不过 `expires_in`。
- **一次性。** 交互往返期间只读取用。authorize 向 client 产出响应（授权码或错误重定向）时，先重新加载 client，再原子取出记录；授权码只在取出成功后签发。并发中落败或 client 已不存在 → `invalid_request`、不签发授权码；取出的其他故障 → 5xx。登录、同意、自定义交互重定向不消费。
- 未经 PAR 的请求：client 要求 PAR 或 `RequireForAllClients` 时 → `invalid_request`。

### 阶段输入（破坏性签名改动）

`validators.AuthorizeRequestValidator.Validate(ctx, values, subject, phase)` 新增 `phase validators.AuthorizeRequestPhase`：`AuthorizeRequestPhaseEntry`（零值，authorize 端点）、`AuthorizeRequestPhaseInteractionReturn`（authorize callback 与 `OidcReturnUrlParser`）、`AuthorizeRequestPhasePush`（PAR 端点）。validator 不按端点推断阶段。

### 回收

核心不清理过期记录；宿主定期调用 `PushedAuthorizationRequestStore.RemoveExpired(ctx, cutoff)`。

## DPoP（RFC 9449）

client 在 token 请求上用 `DPoP` 请求头出示 proof（用自己私钥签名的 JWT，头部带公钥 `jwk`），签发的 access token 绑定到该公钥（`cnf.jkt`），被窃取后没有私钥就无法使用。默认关闭；本版覆盖 token 端点、authorize / PAR 的 `dpop_jkt` 预绑定、可选的服务端 nonce，userinfo / introspection 对绑定 token 的处理，以及资源端 JWT Bearer handler（`auth/jwt`）的 DPoP 校验（见下文"资源端 JWT Bearer handler"与 [外部提供者指南 · JWT Bearer 的 DPoP 校验](./external-providers-guide.md#dpop-校验rfc-9449)）。

### 启用

```go
cfg := root.ServerConfig()
cfg.SetReplayRegistry(hostRegistry) // 重放登记端口，启用后为条件必需
cfg.EnableDPoP(dpop.Options{SigningAlgorithms: []string{"ES256", "PS256"}})
cfg.Freeze()
```

`EnableDPoP` 是唯一开关（`EndpointsOptions` 没有对应开关），在 `Freeze()` 之后调用会 panic；`DPoPEnabled()` 查询，`DPoPOptions()` 返回补齐默认值后的选项。启用后重放登记端口缝为特性条件必需（见[存储持久化接入指南](./storage-persistence-guide.md#重放登记适配器)）；选项不合法时 `Freeze()` panic。

| `dpop.Options` 字段 | 默认 | 含义 |
|------|------|------|
| `SigningAlgorithms` | `clientassertion.SupportedSigningAlgorithms()`（RS/PS/ES 256/384/512） | 接受的 proof 签名算法，只能是该集合的子集，不得重复；`none` 与 `HS*` 永远不接受 |
| `ProofLifetime` | 60s | `iat` 之后 proof 仍被接受的时长，上限 10 分钟 |
| `ClockSkew` | 60s | 判定 `iat` 与服务端 nonce 的时钟偏差容忍，上限 10 分钟 |
| `RequireNonce` | false | 要求每个 proof 携带服务端 nonce（见下文"服务端 nonce"）；开启后 nonce 密钥缝为条件必需 |
| `NonceLifetime` | 5 分钟 | nonce 签发后被接受的时长，不得为负，上限 10 分钟；只在 `RequireNonce` 时起作用 |

client 元数据（`models.ClientDPoPMetadata`，嵌入 `models.Client`）：

| 字段 | 含义 |
|------|------|
| `RequireDPoP` | 该 client 的 token 请求必须带 proof（对应 RFC 9449 §5.2 的 `dpop_bound_access_tokens`）。DPoP 未启用、或该 client 同时 `AllowAccessTokensViaBrowser` 时，该 client 配置无效：`FindClientById` 返回 `storage.ErrInvalidClientConfiguration`，token 请求按无效 client 失败，不会降级为 Bearer |

### token 端点契约

启用后 token 端点按以下顺序处理（DPoP 未启用时完全不读 `DPoP` 头）：

1. **签发 nonce**（仅 `RequireNonce`，且请求带 `DPoP` 头）：生成新 nonce 写入 `DPoP-Nonce` 响应头，此后无论成功失败响应都带它。
2. **proof 无状态校验**（先于客户端认证）。请求带 `DPoP` 头时：只能有一个头字段，值为三段紧凑 JWS；头部 `typ` 为 `dpop+jwt`（大小写不敏感）、`alg` 在配置集合内、`jwk` 为与 `alg` 密钥类型相符的公钥（含私钥成员 `d`/`p`/`q`/`dp`/`dq`/`qi`/`oth`/`k` 即拒绝）、不得出现 `crit`；签名用头部 `jwk` 验证；claims 须有 `jti`（不超过 256 字节）、`htm`（等于请求方法）、`htu`、`iat`（不早于 now − `ProofLifetime` − `ClockSkew`，不晚于 now + `ClockSkew`）。任一不符 → 400 `invalid_dpop_proof`。`ath` 本版不校验；`nonce` 只在 `RequireNonce` 时读取（若出现须为非空字符串、不超过 512 字节，否则 `invalid_dpop_proof`），未开启时忽略。
3. **nonce 质询**（仅 `RequireNonce`）：proof 未带 `nonce`，或 nonce 不被接受（过期、伪造、他面签发、编码损坏）→ 400 `use_dpop_nonce`，带新 `DPoP-Nonce`。质询先于客户端认证与一切登记，不消耗授权码、断言 `jti` 或 proof `jti`，客户端用新 nonce 重做 proof 后可用同一授权码、同一断言重试。
4. **客户端认证**（既有流程，含 `private_key_jwt` 断言 `jti` 登记）。
5. **按 client 强制**：client `RequireDPoP` 而请求未带 proof → 400 `invalid_request`，描述 `DPoP proof required`。这一检查需要先知道 client，因此位于断言 `jti` 登记之后：被拒的客户端重试时需要新的断言。
6. **proof `jti` 登记**：键由 `replay.Key(replay.PurposeDPoPProof(), <proof 公钥指纹>, jti)` 生成，记录过期时刻为 max(`iat` + `ProofLifetime`, nonce 截止时刻, now) + `ClockSkew`（nonce 截止时刻 = nonce 签发时刻 + `NonceLifetime`，未要求 nonce 时不参与）。重复 → 400 `invalid_dpop_proof`；登记端口的其他任何错误 → 固定 500（`text/plain`，`Cache-Control: no-store`），既不判为重放也不放行。
7. 授权码原子取出 / refresh token 读取，随后做授权码 `dpop_jkt` 比对与 refresh token 绑定校验（见下），再签发。

一切 proof 无状态拒绝（含 nonce 质询）都发生在授权码取出之前，所以被拒的授权码可以带合法 proof 再次兑换。

**`htu` 的期望值**由本次请求推导：请求的基础 URL（scheme 由连接是否为 TLS 决定，host 取请求的 `Host`）加请求路径；mTLS 别名路由各自成立。比较时两侧都解析为 URL，scheme 与 host 按小写比较、去掉默认端口、忽略 query 与 fragment，路径（转义形式）逐字节相等，不做百分号编码规范化。TLS 终止于反向代理时，wicket 看到的 scheme 为 `http`，与 issuer 推导的既有行为一致；这种部署下 client 的 `htu` 需与之一致，或由宿主配置使请求呈现正确的 scheme 与 host。

### 绑定

- 带合法 proof 签发的 access token 带 `cnf.jkt`（proof 公钥的 RFC 7638 SHA-256 指纹，base64url 无填充）；JWT 写入 payload，reference token 写入存储副本的 `cnf` claim。响应 `token_type` 为 `DPoP`（`wicket.TokenResponseTypesDPoP`）；不带 proof 时与既有行为一致（`Bearer`）。
- 同时启用 mTLS 证书绑定时，证书绑定 client 带 proof 得到的 `cnf` 同时含 `x5t#S256` 与 `jkt`。
- **public client**（`RequireClientSecret` 为 false）带 proof 获得的 refresh token 记录 proof 公钥指纹（`RefreshToken.DPoPKeyThumbprint`，创建时写入、之后不改）。此后兑换必须带同一密钥的 proof，未带或换用其他密钥 → 400 `invalid_grant`，refresh token 记录不被更新。不带 proof 获得的 refresh token 不会被事后绑定。
- **机密 client** 的 refresh token 不绑定：兑换时带 proof 则新 access token 绑定到本次 proof 的密钥，不带则为 Bearer。

### `dpop_jkt` 预绑定（RFC 9449 §10）

DPoP 启用时，authorize 请求可带 `dpop_jkt`（`wicket.AuthorizeRequestDPoPJkt`）：DPoP 公钥的 RFC 7638 SHA-256 指纹，base64url 无填充（恰好 43 字符，规范编码，解码为 32 字节）。

- 直接请求与经 PAR 推送（推送参数中含 `dpop_jkt`，authorize 用 `request_uri`）效果相同。格式不合法 → `invalid_request`（描述 `Invalid dpop_jkt`）：直接请求显示在错误页，PAR 推送阶段返回 400 `invalid_request`，不签发授权码。
- 指纹随授权码保存（`AuthorizationCode.DPoPKeyThumbprint`，嵌入 `models.AuthorizationCodeProofBinding`）。兑换时授权码先被原子取出，再比对：请求未带 proof，或 proof 公钥指纹与之不同 → 400 `invalid_grant`，此时授权码已作废，换用正确密钥也不能再兑换。
- PAR 端点不读 `DPoP` 头：PAR 请求所带的 `DPoP` 头被忽略，既不校验也不派生绑定。经 PAR 预绑定只能用 `dpop_jkt` 参数。
- DPoP 未启用时 `dpop_jkt` 被忽略：不校验格式、不写入授权码，兑换行为与既有一致。

### 服务端 nonce（RFC 9449 §8）

`dpop.Options.RequireNonce` 开启后，token 端点要求每个 proof 带服务端签发的 `nonce` claim。默认关闭；关闭时 token 端点不发 `DPoP-Nonce`、不读密钥缝，行为与只启用 DPoP 时完全一致。

```go
keys, err := dpop.NewStaticNonceKeys(dpop.NonceKey{Id: "2026-11", Secret: secret32Bytes})
cfg.SetDPoPNonceKeys(keys) // nonce 密钥缝，RequireNonce 时为条件必需
cfg.EnableDPoP(dpop.Options{RequireNonce: true})
cfg.Freeze()
```

- **密钥缝**：`ServerConfig.SetDPoPNonceKeys(dpop.NonceKeySource)`，须在 `Freeze()` 之前调用（之后调用 panic），重复调用替换。`RequireNonce` 开启而未注入，或密钥源读取失败、返回的密钥不合法，`Freeze()` panic（文本含 `dpop nonce key`）。`AllowInMemoryFallback()` 不豁免该缝，也没有逐缝回退声明；它与全局 `dp.DataProtectionProvider` 无关。`RequireNonce` 未开启时任何代码路径都不读取该缝。
- **密钥**：`dpop.NonceKey{Id, Secret}`。`Secret` 至少 32 字节（HMAC-SHA256 密钥）；`Id` 为 1–32 字节的 `[A-Za-z0-9._-]`，且 current 与 previous 之间不得重复。`dpop.ValidateNonceKeys` 做同样的检查；`dpop.NewStaticNonceKeys(current, previous...)` 返回固定密钥源，不合法时返回错误。动态密钥源实现 `NonceKeys() (current, previous, err)`。
- **格式**：nonce 无状态、自验证，不写任何存储，不经重放登记端口。内容为签发时刻、密钥 id 与 MAC（HMAC-SHA256，域分隔串 `wicket dpop nonce v1`，签发面标识为 `authorization-server <issuer>`），base64url 无填充，最长 99 字符。签发面取 issuer 粒度：主路由与 mTLS 别名只在 issuer 相同时互认 nonce，即配置了 `IssuerUri`，或别名与主路由同源；未配置 `IssuerUri` 而别名用独立主机（`MutualTls.DomainName`）时，issuer 取请求来源，各主机各自签发 nonce，客户端在每个主机上各被质询一次。接受条件：密钥 id 在 current 或 previous 中、MAC 相符、签发面相同、签发时刻不晚于 now + `ClockSkew`、now 不晚于签发时刻 + `NonceLifetime` + `ClockSkew`。nonce 在有效期内可用于多个 proof（每个 proof 的 `jti` 仍各自登记）。
- **响应头**：`RequireNonce` 开启时，凡请求带 `DPoP` 头，响应（成功、`use_dpop_nonce`、`invalid_dpop_proof` 及其他 400）都带新的 `DPoP-Nonce`（`wicket.DPoPNonceHeaderName`）；请求不带 `DPoP` 头时与既有行为一致，不发该头。nonce 签发或校验所需的密钥源读取失败、返回不合法密钥，或 issuer 无法确定 → 固定 500（同重放登记故障），日志只记错误类型。
- **多副本与轮换**：所有副本注入同一密钥源；密钥源在每次签发与校验时重新读取，动态实现可热轮换。轮换三步：① 新密钥先作为 previous 部署到全部副本；② 再切为 current；③ 旧密钥在 previous 中保留至少 `NonceLifetime` + `ClockSkew` 后移除。
- **浏览器客户端**：wicket 不设 CORS 暴露头；浏览器端 JavaScript 要读取 `DPoP-Nonce`，宿主须在自己的 CORS 层加 `Access-Control-Expose-Headers: DPoP-Nonce`。
- nonce 模式下仍判 `iat` 新鲜度。RFC 9449 没有宣告 nonce 的 discovery 元数据，discovery 不变。

### 错误码

| 情形 | 错误码 |
|------|------|
| proof 无效、`jti` 重放 | `invalid_dpop_proof`（RFC 9449 §5 为 token 端点定义） |
| client 要求 DPoP 而未带 proof | `invalid_request`（wicket 的选择） |
| 绑定的 refresh token 未带 proof 或换用其他密钥 | `invalid_grant`（wicket 的选择，不区分两种情形） |
| 授权码带 `dpop_jkt` 而未带 proof 或换用其他密钥 | `invalid_grant`（授权码已作废） |
| `RequireNonce` 开启，proof 缺 nonce 或 nonce 不被接受 | `use_dpop_nonce`（RFC 9449 §8），响应带 `DPoP-Nonce` |
| userinfo：proof 缺失 / 无效 / 重放、`ath` 不符 | `invalid_dpop_proof`（401，DPoP 质询） |
| userinfo：token 无效 / 过期 / 未绑定、指纹不符、`cnf` 畸形、证书绑定失败，或绑定 token 以 Bearer 出示 | `invalid_token`（401） |
| userinfo：`DPoP` 授权头畸形，或同时带表单 `access_token` | `invalid_request`（400） |

`DPoP-Nonce` 响应头只在 `RequireNonce` 开启且请求带 `DPoP` 头时发出（见上文"服务端 nonce"）。

### userinfo 与 introspection

**userinfo**（RFC 9449 §7）。DPoP 启用时 userinfo 接受 `Authorization: DPoP <access token>`（方案名大小写不敏感，`wicket.AuthenticationSchemesAuthorizationHeaderDPoP`；方案后一个或多个空格，token 非空且不含空白）。处理顺序：

1. 解析授权头：`DPoP` 后无 token、token 含空白，或同时在表单带 `access_token` → 400 `invalid_request`。
2. proof 无状态校验：与 token 端点相同的全部检查（`htm` 为本次请求方法，`htu` 为 userinfo 的 URL），并要求 `ath` 为字符串且等于该 access token 的 SHA-256 摘要（ASCII 字节，base64url 无填充，`dpop.AccessTokenHash`）。缺 proof、多个 proof、`ath` 缺失 / 非字符串 / 不符 → 401 `invalid_dpop_proof`。
3. token 校验（与 Bearer 相同的路径）：无效 → 401 `invalid_token`；过期 → 401 `invalid_token` 带描述 `The access token expired`；scope 不足 → 403 `insufficient_scope`。
4. 绑定比对：token 必须带 `cnf.jkt`，且等于 proof 公钥指纹（常量时间比较）。未绑定、指纹不符、`cnf` 畸形 → 401 `invalid_token`。
5. 证书绑定检查（`cnf.x5t#S256`，见 [mTLS 指南](./mtls-client-auth-guide.md#资源端校验)）：两种绑定同时存在时都须满足，否则 401 `invalid_token`。
6. proof `jti` 登记（键与过期时刻同 token 端点）：重放 → 401 `invalid_dpop_proof`；登记端口故障 → 固定 500（`Internal Server Error`，`Cache-Control: no-store`，日志只记错误类型），不返回 claims。
7. 返回 claims，内容与 Bearer 出示时相同。

任何拒绝都先于登记，被拒请求不消耗 proof `jti`。服务端 nonce 不适用于 userinfo：`RequireNonce` 开启时 userinfo 仍只判 `iat` 新鲜度，proof 中格式合法的 `nonce` 被忽略（格式不合法仍按 `invalid_dpop_proof` 拒绝），不发 `DPoP-Nonce`。

**质询头**：DPoP 方案路径上的一切 4xx，以及 DPoP 启用时绑定 token 以 Bearer 出示的拒绝，都只带一个头值

```
WWW-Authenticate: DPoP error="<code>"[, error_description="<desc>"], algs="<配置的算法，空格分隔>"
```

并带 `Cache-Control: no-store`，无响应体。`invalid_dpop_proof` 为 401，其余错误码的状态码同 Bearer（`invalid_request` 400、`insufficient_scope` 403、其他 401）。

**绑定 token 不得以 Bearer 出示**（RFC 9449 §7.2）：带 `cnf.jkt` 的 token 以 `Authorization: Bearer` 或表单 `access_token` 出示，且 token 本身校验通过时，回 401 `invalid_token`（有无 `DPoP` 头都一样）；`cnf` 畸形（不是对象或 JSON 损坏、`jkt` 不是非空字符串、多个 `cnf`）同样拒绝。这一拒绝在 token 校验之后判定：token 无效、过期或 scope 不足时，仍按既有方式回校验器给出的错误（如 403 `insufficient_scope`）。DPoP 启用时发上述 DPoP 质询，未启用时用既有 Bearer 结果。`cnf` 可以是对象，也可以是适配器往返后的 JSON 文本，两者等价。未绑定的 token 以 Bearer 出示时行为不变，请求所带的 `DPoP` 头被忽略。

DPoP 未启用时 userinfo 不识别 `DPoP` 方案（与此前一致，按缺少 Bearer token 回 401），也不解析重放登记端口。

未出示任何 token 的请求仍只回 Bearer 质询。

**introspection**：active 响应对绑定的 token 返回 `cnf`（`{"jkt":"<指纹>"}`，与证书绑定并存时同时含 `x5t#S256`），JWT 与 reference token 一致；未绑定 token 不含 `cnf`。响应不含 `token_type`。reference token 的 `cnf` 取自存储副本的 `cnf` claim，按存入的形态原样返回。

### 资源端 JWT Bearer handler

用 wicket 自带 JWT Bearer handler 保护 API 的资源服务器，经 `jwt.NewDPoPValidation(jwt.DPoPValidationConfig{...})` 构造校验对象并挂到 `jwt.Options.DPoP` 上开启；不读 `ServerConfig`、不经容器注册（资源服务器多半不是授权服务器进程）。开启后 handler 接受 `Authorization: DPoP <access token>`，校验 proof（含 `ath`、`htm`/`htu`、`iat`，nonce 模式下另判本资源签发的 nonce）、`cnf.jkt` 匹配与 `jti` 防重放；绑定 token 以 Bearer 出示被拒。错误码与质询头同 userinfo（`invalid_dpop_proof`、`invalid_token`、`invalid_request`），nonce 模式另有 `use_dpop_nonce` 与 `DPoP-Nonce`，未出示 token 时回 `DPoP algs="…"`。详见 [外部提供者指南 · JWT Bearer 的 DPoP 校验](./external-providers-guide.md#dpop-校验rfc-9449)。`Options.DPoP` 为 nil 时 handler 行为与此前完全一致。

### Discovery

DPoP 启用时 discovery 文档写入 `dpop_signing_alg_values_supported`（配置的算法列表）；未启用时不宣告。该键只由 discovery handler 写入，宿主自定义的同名条目被删除并记录告警。

## 账户创建（`prompt=create`）

OpenID Connect Prompt Create 1.0 为 `prompt` 增加取值 `create`（`wicket.PromptModesCreate`）：RP 请求 OP 展示账户创建界面而不是登录界面。wicket 不带 UI，账户创建页由宿主提供。

### 配置

```go
cfg := root.ServerConfig()
cfg.SetAccountCreationUrl("/account/register") // 或 "https://accounts.example/register"
cfg.Freeze()
```

- `SetAccountCreationUrl(url)` 接受本地路径（以 `/` 或 `~/` 开头）或带主机的 `http` / `https` 绝对 URL，去掉首尾空白后保存；空值、其他形式或 `Freeze()` 之后调用都会 panic。重复调用以最后一次为准。`AccountCreationUrl()` 返回已声明的地址，未声明时为空串。
- 没有 `UserInteractionOptions` 字段或 `EndpointsOptions` 开关与之对应。

### authorize 行为

- **已配置**：`prompt` 含 `create` 的请求（无论用户是否已登录）经既有自定义重定向交互结果被送到账户创建页，地址后附 `UserInteraction.CustomRedirectReturnUrlParameter`（默认 `returnUrl`）指向 `connect/authorize/callback` 的返回 URL，参数携带方式与登录页、同意页相同（内联或经 `AuthorizationParametersMessageStore` 句柄）。返回 URL 是相对 wicket base URL 的服务器相对路径；账户创建页若声明为其他主机上的绝对 URL，须自行按 wicket 的 base URL 解析该路径，并能在 wicket 所在站点签发登录会话。账户创建页经 `InteractionService.GetAuthorizationContext(returnUrl)` 取得请求，其 `PromptModes` 含 `create`。
- **宿主页职责**：创建账户并让用户登录（签发登录会话），然后跳回 returnUrl。回到 callback 时不再进入账户创建页。
- **组合**：跳转前，`prompt` 中的 `create`、`login`、`select_account` 并入 `suppressed_prompt` 随 returnUrl 往返，所以 `create login`、`create select_account` 回来后不再强制登录 / 选择账户；`consent` 不属认证，`create consent` 回来后照常进入同意页。已配置时，`none` 与 `create`（或任何其他值）同时出现返回 `invalid_request`（`Invalid prompt`）；未配置时含 `create` 的列表先按下条拒绝。
- **未配置**：`prompt` 含 `create` 时返回 `invalid_request`，`error_description` 为 `prompt value create is not supported`，经既有 authorize 错误分发（错误页，错误消息中带回 client 的重定向地址；PAR 端点为 400）。**行为变化**：此前未知的 `create` 使整条 `prompt` 被静默忽略。
- 含其他未知值的列表（如 `create foo`）仍按以往整条忽略；不含 `create` 的请求行为不变。
- PAR：推送的 `prompt=create` 同样生效；未配置时推送端点直接返回 400 `invalid_request`。

### Discovery

已配置且 settle 后文档含 `authorization_endpoint` 时，openid-configuration 与授权服务器元数据宣告 `prompt_values_supported`（`wicket.DiscoveryPromptValuesSupported`）：`["none","login","consent","select_account","create"]`；否则不宣告。该键只由 handler 写入（组合根在已配置时调用 `(*handlers.DiscoveryHandler).ServeAccountCreation()`），宿主同名自定义条目被删除并记录告警（未配置时同样删除）。未配置且宿主没有该自定义条目时，discovery 文档不变。

## 强制满足所请求的 acr（`unmet_authentication_requirements`）

OpenID Connect Core 把 `acr_values` 视为 Voluntary claim：无法满足时 OP 应返回会话当前的 `acr`，所以默认装配照常签发授权码，不比较会话 `acr` 与请求值。宿主可以开启强制：开启后，RP 用 `acr_values` 请求的认证强度得不到满足时，client 会收到 `error=unmet_authentication_requirements`（`wicket.AuthorizeErrorsUnmetAuthenticationRequirements`，见 OpenID Connect Core Error Code unmet_authentication_requirements 1.0 §1），而不是一个静默降级的授权码。

### 开启

```go
cfg := root.ServerConfig()
cfg.RequireRequestedAcr()
cfg.Freeze()
```

- `RequireRequestedAcr()` 须在 `Freeze()` 之前调用，之后调用会 panic；重复调用幂等。`RequestedAcrRequired()` 查询是否已开启。默认关闭，关闭时行为与以往完全相同。
- 组合根据此调用 `(*responses/impl.AuthorizeInteractionResponseGenerator).RequireRequestedAcr()`。没有 discovery 键与之对应。

### 判定依据

- 请求值集合取 `acr_values`，去掉以 `idp:`、`tenant:`（`wicket.KnownAcrValuesAll`）开头的值：它们是路由提示，不是认证强度，处理方式不变。
- 会话 `acr` 取当前登录主体的第一个 `acr` claim（`wicket.JwtClaimTypesAuthenticationContextClassReference`，字符串值），没有时为空串。它由宿主在登录页签发登录会话时写入主体，这是宿主报告认证强度的唯一通道。wicket 不对 acr 排序或映射。
- 满足的条件：去掉提示前缀后没有请求值，或会话 `acr` 与某个请求值逐字相等。

### authorize 行为（仅在开启时）

- **满足**：照常进入同意判定并签发响应，不经过登录页。
- **不满足，尚未登录过**：送往登录页（step-up），宿主可借此提升认证强度后重新签发登录会话。跳转前把 `login` 并入 `suppressed_prompt`（与已有值求并、去重、保序），随 returnUrl 往返，作为「本次授权已经过一次交互登录」的标记。未登录用户在请求带 `acr_values` 时同样带上该标记；`prompt=login` 的请求本来就会抑制 `login`。
- **不满足，已经过登录页**（`suppressed_prompt` 含 `login`）：返回 `unmet_authentication_requirements`，`error_description` 为 `requested acr_values could not be satisfied`。登录页只经过一次。
- **`prompt=none`**：会话存在但不满足时直接返回 `unmet_authentication_requirements`；没有会话时仍是 `login_required`。
- 错误投递到 client 的 `redirect_uri`，遵守 response_mode（query、fragment、form_post），带 `state`（以及在开启 `EmitIssuerIdentificationResponseParameter` 且响应带签发者时的 `iss`），不进入错误页。
- `max_age` 的既有处理不变：会话超龄时强制登录，`prompt=none` 下返回 `login_required`。`claims` 请求参数不受支持，ID token 中 `acr` 的签发不变。
- PAR：推送的 `acr_values` 同样生效；返回该错误时 `request_uri` 被消费。
- 强制只作用于 authorize 端点（含经 PAR 推送的请求），不作用于 backchannel authentication（CIBA）。
- **宿主登录页职责**：登录页须经 `GetAuthorizationContext` 读取 `AuthorizationRequest.AcrValues` 并真正重新认证，签入满足要求的 `acr`；对已登录用户直接跳回 returnUrl 的登录页会让请求以 `unmet_authentication_requirements` 结束。
- `prompt=create` 的账户创建往返只抑制请求中出现过的 `create`、`login`、`select_account`。单独的 `prompt=create` 不会抑制 `login`：账户创建后 `acr` 仍不满足时照常 step-up 一次，`create` 保持抑制，不会再进注册页。`prompt=create login` 已抑制 `login`，视为已经过交互登录，此时直接返回该错误。
- client 自行携带 `suppressed_prompt=login` 时不会经过 step-up，不满足即返回该错误，不会因此拿到授权码。

## 第三方发起登录（OpenID Connect Core §4）

OpenID Connect Core 1.0 §4 允许第三方（门户、OP 侧入口页等）把用户送到 RP 的登录发起端点，由 RP 向 OP 发起认证请求。wicket 不新增协议端点、路由或 discovery 宣告；它在 client 模型上登记该端点，并提供让宿主构造、发起这次跳转的函数（包 `thirdpartylogin`）。

### client 元数据

- `Client.InitiateLoginUri`（内嵌结构 `models.ClientThirdPartyLoginMetadata`）对应 OpenID Connect Dynamic Client Registration 1.0 §2 的 `initiate_login_uri`。空串表示未登记，配置合法。
- 非空时须能解析（含 query 可解析为参数对）、为绝对 URI、scheme 为 `https`（大小写不敏感）、host 非空（`models.IsAbsoluteHttpsUri`）；不满足即 client 配置无效：经 `storage.ClientStore` 读取返回 `storage.ErrInvalidClientConfiguration`（`extensions.IsClientRejected` 为 true），与其他 client 元数据规则同在 `ClientConfigurationValidator`、同在读路径 fail-closed。该规则不依赖任何特性开关，静态 client 列表与宿主注入的 client store 都适用；没有允许 http 的开关。
- 装配期：`SetClients` / `SetClientsProvider` 登记的静态 client 列表在 `ServerConfig.Freeze()` 时即被检查，任一 client 的 `InitiateLoginUri` 非空且不满足上述判定即 panic，文本含该 client id（只检查这一字段）。宿主注入的 client store 在装配期不可见，仍由读路径拒绝。
- 经动态客户端注册读写该元数据暂不支持，由后续版本提供。

### 发起

```go
mux.HandleFunc("/portal/start", func(w http.ResponseWriter, r *http.Request) {
	err := thirdpartylogin.Initiate(w, r, "rp-client", thirdpartylogin.Parameters{
		LoginHint:     "alice@example.com",
		TargetLinkUri: "https://rp.example/app",
	})
	if err != nil {
		// 响应未被写入，宿主自行处置（错误页、404 等）
	}
})
```

- `thirdpartylogin.Initiate(w, r, clientId, params)` 须在 wicket 请求作用域内运行（宿主 handler 位于 `hosting.ScopeMiddleware` 与 `Server.UseWicket()` 之后）。它经作用域内的 `storage.ClientStore`（即带配置校验的 store）用 `extensions.FindEnabledClientById` 读取 client，`iss` 取自 `services.IssuerNameService.GetCurrent()`，成功时返回 `302 Found`，`Location` 为发起 URL，带 `Cache-Control: no-store`。
- `thirdpartylogin.BuildInitiationUrl(client, issuer, params)` 是纯构造：在登记 URI 的 query 上设置 `iss`、`login_hint`、`target_link_uri`；登记 URI 自带的其他参数原样保留，这三个同名参数一律被替换，空的可选参数不出现（登记 URI 自带的同名值也被去掉）。query 按 `url.Values.Encode` 排序，例如登记 `https://rp.example/login?tenant=a`、issuer `https://op.example`、hint `alice` 得到 `https://rp.example/login?iss=https%3A%2F%2Fop.example&login_hint=alice&tenant=a`。
- 只产出 GET 形态；不提供自动提交表单的 POST 形态（Registration §2 要求 RP 同时接受两者）。
- `iss` 必须是带 host 的 https URL（Core §4 的 MUST）。未配置 `IssuerUri` 时 issuer 取当前请求的 origin，在 http 上运行的开发环境会因此报错；须配置 https 形式的 `IssuerUri` 才能使用发起能力。
- `target_link_uri` 非空时须为带 host 的绝对 http 或 https URL（scheme 大小写不敏感）；wicket 不限制其 origin。开放重定向防护由 RP 负责：RP 跳转前须自行校验 `target_link_uri`。
- `login_hint` 可能是邮箱或手机号，该包不写日志，错误文本中也不含它。

### 错误

出错时不写响应（头与正文皆不动），返回可用 `errors.Is` 区分的错误：

| 情形 | 错误 |
|------|------|
| 请求不在 wicket 作用域内 | `thirdpartylogin.ErrNoRequestScope` |
| client 不存在或已停用 | 包装 `storage.ErrNotFound` |
| client 配置无效（含非 https 的 `InitiateLoginUri`） | 包装 `storage.ErrInvalidClientConfiguration` |
| client 读取的其他故障 | 原样包装 store 的错误 |
| client 未登记 `InitiateLoginUri` | `thirdpartylogin.ErrNotRegistered` |
| 登记值不是绝对 https URI（仅纯构造函数直接收到未经校验的 client 时） | `thirdpartylogin.ErrInvalidInitiateLoginUri` |
| issuer 不是带 host 的 https URL | `thirdpartylogin.ErrInvalidIssuer` |
| `target_link_uri` 不是绝对 http 或 https URL | `thirdpartylogin.ErrInvalidTargetLinkUri` |

前三类 client 错误可用 `extensions.IsClientRejected` 与基础设施故障区分。

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
| `DPoP`（userinfo） | DPoP 绑定的 access token，随 `DPoP` proof 出示；仅 DPoP 启用时识别，见上文"userinfo 与 introspection" |
| `DPoP`（JWT Bearer handler） | 同上，由 `Bearer` scheme 的 JWT handler 在 `jwt.Options.DPoP` 设置时识别，见上文"资源端 JWT Bearer handler" |
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
| `introspection_signing_alg_values_supported` | 仅由 handler 写入：装配声明了签名内省响应（组合根总是声明），settle 后文档的 `introspection_endpoint` 是本服务 base URL 下的 `connect/introspect` 路由（路径不区分大小写），且 `KeyMaterialService.GetAllSigningCredentials` 至少有一个凭据时，写入全部凭据算法（去重，保持首次出现顺序，与 `id_token_signing_alg_values_supported` 同源）；否则不宣告。宿主同名自定义条目被删除并记录告警。读取凭据失败时 discovery 请求返回错误（中间件既有 5xx） |
| `tls_client_auth` / `self_signed_tls_client_auth` | 逐个判定：该方法在已注册解析器的 `GetAvailableAuthenticationMethods()` 中 |
| `tls_client_certificate_bound_access_tokens`、`mtls_endpoint_aliases` | 至少注册了一种 tls 类客户端认证解析器。alias 条目逐条判定：对应主端点仍被宣告，且路径形态（未配置 `MutualTls.DomainName`）的 alias 路径已注册为端点路由（配置了 `DomainName` 的 domain / sub-domain 形态位于其他主机，只看主端点）；删空后整个键移除 |
| `pushed_authorization_request_endpoint` / `require_pushed_authorization_requests` | 仅由 handler 写入：PAR 已启用且其路由已注册时写入端点 URL 与是否全局强制；否则两键一律移除（宿主同名自定义条目同样被移除）。`mtls_endpoint_aliases` 已宣告且 mTLS 别名路由已注册时追加 PAR 别名（路径形态 `connect/mtls/pushedauthorization`，或按 `MutualTls.DomainName` 的 domain / sub-domain 形态） |
| `prompt_values_supported` | 仅由 handler 写入：装配声明了账户创建页（`ServerConfig.SetAccountCreationUrl`）且 settle 后文档含 `authorization_endpoint` 时写入 `none`、`login`、`consent`、`select_account`、`create`；否则不宣告。宿主同名自定义条目被删除并记录告警。见「账户创建（`prompt=create`）」 |

令牌撤销端点与设备授权端点已注册，`revocation_endpoint`、`device_authorization_endpoint` 以及 `grant_types_supported` 中的 `device_code` 在默认装配下照常输出；`EnableDeviceAuthorizationEndpoint=false` 时后两者不输出；`EnableTokenRevocationEndpoint=false` 时 generator 不输出 `revocation_endpoint`，宿主未配置同名自定义条目时文档中没有该键。授权、令牌、内省、CIBA 四个端点的开关同理，关闭时 generator 不输出下列键，宿主未配置同名自定义条目时文档中没有这些键：`EnableAuthorizeEndpoint=false` 时为 `authorization_endpoint`、`request_parameter_supported`、`request_object_signing_alg_values_supported`，以及 `EnableJwtRequestUri=true` 时才有的 `request_uri_parameter_supported`；`EnableTokenEndpoint=false` 时为 `token_endpoint`；`EnableIntrospectionEndpoint=false` 时为 `introspection_endpoint`；`EnableBackchannelAuthenticationEndpoint=false` 时为 `backchannel_authentication_endpoint`、`backchannel_token_delivery_modes_supported`、`backchannel_user_code_parameter_supported`，以及 `grant_types_supported` 中的 `urn:openid:params:grant-type:ciba`。authorize 或 token 端点关闭后，`response_types_supported`、`response_modes_supported`、`grant_types_supported`、`token_endpoint_auth_methods_supported` 等仍照常输出。`frontchannel_logout_*` 照常输出（不开启 server-side sessions 时 front-channel 通知不会发生，见下文 Back-Channel Logout 的已知限制）。宿主通过 `Discovery.CustomEntries` 添加的条目不参与过滤，但键名与生成键相同的除外。生成键指 generator 会写入文档的键，其中多数按开关写入：开关打开时 generator 丢弃同名自定义值；开关关闭时 generator 不写该键，同名自定义值会进入文档。两种情况下，这些键下的值一律按上表过滤（列表值无论是 `[]string` 还是从配置解码出的 `[]any` 都逐项判定）。上表按装配事实判定，端点开关不是过滤条件。被过滤撤下的能力，宿主无法借生成键名重新宣告：就端点而言，路径未注册为端点路由时，同名自定义值若指向本服务 base URL 下的该路径（包括宿主在 wicket 端点路由之外自行提供的路径），或不是绝对 URL，照样被撤下，即使自定义值与生成值相同。开关关闭而路由仍已注册时则不被撤下：`EnableTokenRevocationEndpoint=false` 时 generator 不写入 `revocation_endpoint`，端点对任何请求返回 404；宿主此时若以同名自定义条目写入指向本服务撤销路由的值，或任何外部绝对 URL，该值会出现在 discovery 文档中。其中指回本服务撤销路由的情形是已知限制：文档宣告了一个返回 404 的端点，开关关闭时，宿主不应以该键指回本服务的撤销路由。同一已知限制也适用于 `authorization_endpoint`、`token_endpoint`、`introspection_endpoint`、`backchannel_authentication_endpoint`：对应开关关闭而宿主以同名自定义条目指回本服务的对应路由时，条目仍出现在文档中，而该端点返回 404；开关关闭时，宿主不应以这些键指回本服务路由。`request_parameter_supported`、`request_object_signing_alg_values_supported`（authorize 关闭时）与 `backchannel_token_delivery_modes_supported`、`backchannel_user_code_parameter_supported`（CIBA 关闭时）的同名自定义值同样会进入文档。宿主自有的能力请用 generator 从不写入的键名宣告（例如 `registration_endpoint`），这类键只可能来自宿主，原样保留。

`MutualTls.Enabled=true` 且有任何 mTLS 相关值（上表最后两行）被移除时，每生成一次文档记一条 `slog` Warn。

### 授权服务器元数据（RFC 8414）

`AuthorizationServerMetadataHandler` 提供 OAuth 2.0 授权服务器元数据文档，供只实现 OAuth 2.0 的 client 发现端点与能力。

- **同源**：文档由装配中同一个 `DiscoveryHandler` 的同一套生成、过滤与 settle 步骤（每个请求各自生成）产出，与 `/.well-known/openid-configuration` 键集合相同、每个键取值相同（包括 OIDC 专属键；RFC 8414 允许附加元数据）。上文按装配事实过滤的规则同样适用。新路由本身不写进任何文档键。
- **路径规则**（RFC 8414 §3）：服务路径 = `/.well-known/oauth-authorization-server` + 文档 `issuer` 的转义路径部分（去掉末尾所有 `/`）。issuer 无路径或只有 `/` 时为裸路径。例：issuer `https://as.example/tenant/one/` → `/.well-known/oauth-authorization-server/tenant/one`。`wicket.AuthorizationServerMetadataPath(issuer)` 按同一规则计算，宿主可直接调用。
- **部署不对称**：issuer 含路径时，AS 元数据位于根下的 `/.well-known/oauth-authorization-server/<issuer 路径>`，而 openid-configuration 仍位于根下的 `/.well-known/openid-configuration`（不在 issuer 路径之下），因此 wicket 前面的代理必须把这两条根路径的 well-known 请求转发给 wicket。
- **匹配**：前缀按端点路由口径不区分大小写；其后的 issuer 路径按转义形式逐字节比较。
- **开关与检查顺序**：沿用 `Endpoints.EnableDiscoveryEndpoint`，无独立开关。先检查方法，再检查开关：非 GET 请求一律 405（开关关闭时也是 405），GET 请求在开关关闭时 404。
- **404**：GET 请求在开关关闭时、或前缀下的路径与服务路径不符（例如 issuer 含路径时访问裸路径，或 issuer 无路径时访问 `…/oauth-authorization-server/x`、`…/oauth-authorization-server/`）时返回 404（空响应体），不落到宿主的下一个 handler。
- **路由行为变化**：`/.well-known/oauth-authorization-server/` 下任何未被其他路由命中的请求现在都由 wicket 应答（路径不符时 404），不再到达宿主的下一个 handler；宿主在该前缀下自行挂载的路由会被遮盖。
- **CORS**：路由未加入 `CorsPaths`。

## 客户端认证方式

| 方式 | 实现 |
|------|------|
| `client_secret_basic` | `BasicAuthenticationSecretParser` |
| `client_secret_post` | `PostBodySecretParser` |
| `client_secret_hashed` | `HashedSharedSecretValidator` |

## 收紧选项（默认全关）

三项收紧选项可单独开启、任意组合，均默认关闭；关闭时行为与以往完全相同。前两项在 `ServerConfig` 上声明，须在 `Freeze()` 之前调用，之后调用会 panic；重复调用幂等。

```go
cfg := root.ServerConfig()
cfg.RequireAsymmetricRequestObjects()        // request object 只收非对称签名
cfg.RequireClientCredentialsAuthentication() // client_credentials 必须真正认证
cfg.Freeze()
```

| 选项 | 查询方法 | 开启后的行为 |
|------|----------|--------------|
| `RequireAsymmetricRequestObjects()` | `AsymmetricRequestObjectsRequired()` | `request` 与 `request_uri` 两条路径的 request object 只接受 `RS256/384/512`、`PS256/384/512`、`ES256/384/512` 签名。`HS*`、`none`、头部无法解析、JSON 序列化或多签名一律 `invalid_request_object`。验签只使用 client 登记的非对称密钥：对称（`kty=oct`）密钥在验签前被剔除，所以头部写 `RS256`、实际用对称密钥做 HMAC 的请求同样被拒；只登记了对称密钥的 client 无法再使用 request object。discovery 的 `request_object_signing_alg_values_supported` 只宣告上述九个值（宿主同名自定义值同样过滤），过滤后为空则删除该键。CIBA 的 `request` 参数不在此范围内 |
| `RequireClientCredentialsAuthentication()` | `ClientCredentialsAuthenticationRequired()` | token 端点上 `grant_type=client_credentials`（请求体或查询串）的请求，只签发给真正认证的 client：`RequireClientSecret=true` 且 secret 正确（implicit-only client 除外）、`private_key_jwt` 断言认证成功，或 tls 类方法以证书认证成功。公开 client（`RequireClientSecret=false`）只带 `client_id` 或带任意 secret 都返回 HTTP 400 `invalid_client`（RFC 6749 §4.4）。其他 grant 与其他端点（撤销、CIBA、设备授权）不受影响 |

强制满足所请求的 acr 同样在 `ServerConfig` 上开启（`RequireRequestedAcr()`），见「强制满足所请求的 acr（`unmet_authentication_requirements`）」。

强制 PAR 不在上表：它随 PAR 特性启用，经 `pushedauth.Options.RequireForAllClients`（全局）或 client 元数据 `RequirePushedAuthorizationRequests`（按 client）开启，见「推送授权请求（PAR）」。

第三项是 client 元数据：`ClientAuthenticationMetadata.TokenEndpointAuthSigningAlgorithms` 为 `private_key_jwt` client 限定断言签名算法，见 [private_key_jwt 接入指南](private-key-jwt-guide.md#按-client-的签名算法白名单)。

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

### JWT 形式的内省响应（RFC 9701）

资源服务器可要求 introspection 端点以签名 JWT 返回内省结果，以便转发给第三方或事后校验来源。

- **请求**：在 `Accept` 请求头中列出 `application/token-introspection+jwt`（`wicket.MediaTypesTokenIntrospectionJwt`）。判定按逗号拆分媒体范围，去掉参数后不区分大小写比较；该项 `q` 为 0（或无法解析）时不算请求，缺省视为 1。`*/*`、`application/*` 等通配不触发 JWT。其他请求（包括无 `Accept`）一律返回与此前完全相同的 JSON。
- **响应**：200，`Content-Type: application/token-introspection+jwt`，`Cache-Control`/`Pragma` 与 JSON 内省响应相同，body 为紧凑序列化 JWT（无末尾换行）。JOSE 头 `typ` 为 `token-introspection+jwt`（`wicket.JwtTypesTokenIntrospection`），`alg` 为签名凭据的算法，凭据有 key id 时带 `kid`。载荷顶层恰好四个 claim：`iss`（当前 issuer）、`aud`（已认证 API 的名称，字符串）、`iat`（签发时刻，Unix 秒）与 `token_introspection`（`wicket.ClaimTypesTokenIntrospection`，即 JSON 形态的内省对象，原样；非活跃 token 为 `{"active":false}`）。顶层不放 `sub`、`exp`、`jti` 等其他 claim，因此该 JWT 不会被当作访问令牌或 ID token。
- **签名来源**：`KeyMaterialService.GetSigningCredentials(ctx, nil)`，即 KeyManagement 的统一选择规则，不按 API 的 `AllowedAccessTokenSigningAlgorithms` 限定。签名可用 discovery `jwks_uri` 公布的 JWKS 验证。取不到凭据或签名失败时请求以错误结束（中间件既有 5xx），不回退到 JSON。
- **错误路径**：开关关闭（404）、非 POST（405）、非表单（415）、表单解析失败（400）、API 认证失败（401）、认证不可用、请求校验失败（400）的响应与此前完全相同，不看 `Accept`。
- **宣告**：discovery 与授权服务器元数据文档宣告 `introspection_signing_alg_values_supported`，条件见下文「按装配事实过滤」。
- **装配**：组合根总是为 introspection handler 注入签名依赖（`(*handlers.IntrospectionHandler).ServeSignedResponses`），并为 discovery handler 声明签名内省（`(*handlers.DiscoveryHandler).ServeSignedIntrospection`），无新增开关。以 `handlers.NewIntrospectionHandler` / `NewIntrospectionHandlerWithOptions` 直接构造且未调用 `ServeSignedResponses` 的 handler 对任何请求都返回 JSON（RFC 9701 允许不支持的服务器这样做）。
- **不支持**：JWT 内省响应的加密（`introspection_encrypted_response_alg` / `_enc`）与资源服务器自选签名算法（`introspection_signed_response_alg`）。

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
| `ClientStore` | 客户端注册查询（可选缝 `SetClientStore`，与 `SetClients` 互斥） |
| `ClientOriginLookup` | 按 CORS origin 查询 client；注入的 client store 须同时实现 |
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
| `PushedAuthorizationRequestStore` | 推送授权请求（RFC 9126）；PAR 启用时为特性条件必需缝，过期记录由宿主调用 `RemoveExpired` 回收 |

存储缝分类：`AuthorizationParametersMessageStore` 与 `ClientStore` 为可选缝（未注入时 `Freeze()` 记 WARN、不失败），其余十条为必需缝。

client 读路径哨兵：`storage.ErrNotFound`（client 不存在）、`storage.ErrInvalidClientConfiguration`（记录存在但配置校验失败）；判定函数 `extensions.IsClientRejected(err)` 对二者返回 true。存在性闸门：token 端点客户端认证（含 device authorization、CIBA、revocation 共用的认证器）对被拒 client 答 `invalid_client`，内省答 `{"active":false}`，userinfo / end_session 走既有无效令牌处置；client store 其他错误一律 5xx（认证路径为 500 固定体 `Internal Server Error`）。外部资源服务器离线验签 JWT 不经 wicket，接受到 `exp` 为止。详见 [存储持久化接入指南](./storage-persistence-guide.md)。

### session 族（`session/session.go`）

| 接口 | 用途 |
|------|------|
| `session.Store` | 服务端会话（`SessionID` 键、按 subject 批量吊销、过期清理） |

### keymgmt 族（`keymgmt/record.go`）

| 接口 | 用途 |
|------|------|
| `keymgmt.RecordStore` | 签名密钥记录（乐观并发、四阶段生命周期） |

内存实现（开发用）通过 `di/inmemory.go` 的扩展方法注册；持久化适配器接入见 [存储持久化接入指南](./storage-persistence-guide.md)。
