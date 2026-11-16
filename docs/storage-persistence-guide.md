# 存储持久化接入指南

> 状态：**目标形态已落地**。本文对应 wicket `v0.5.0`，契约套件 `storagetest` / `sessiontest` / `keymgmttest` 为 `2.0.0`（`replaytest` 单独计版本，为 `1.0.0`）；从 `1.1.0` 升级见「升级到契约套件 2.0.0（v0.5.0）」。使用 Go 1.27 工具链时适配器仓即可直接 `require github.com/gonewx/wicket`。
> 权威约束见 ARCHITECTURE-SPINE（AD-2 至 AD-22；该文档位于开发工作区 `_bmad-output/` 下，不随发布产物分发，适配器作者如需查阅请自开发仓库获取）。

## 概述

wicket 的存储端口分三族，职责与持久化必要性各不相同：

| 端口族 | 位置 | 存的是什么 | 不持久化的后果 |
| --- | --- | --- | --- |
| `storage` | `storage/interfaces.go` | 授权码、refresh token、reference token、用户同意、grant、设备码、CIBA 请求；可选的 client 读取与 client 注册、推送授权请求（PAR） | 进程重启后已签发的 refresh token 与 reference access token 全部失效；多副本部署下授权码换令牌随机失败，reference access token 的内省结果随副本而异；推送到一个副本的 `request_uri` 到另一个副本得 `invalid_request_uri`；已注册的 client 重启即丢失 |
| `session` | `session/` | 服务端会话记录 | 重启即全员登出；多副本下会话不共享 |
| `keymgmt` | `keymgmt/` | 签名密钥及其轮换状态 | 每次重启换签名密钥，已签发的 JWT 全部验签失败 |

**只用外部凭据验签的宿主不受影响。** `oidcverify` / `wechatverify` / `phoneverify` 三个包无状态、不依赖任何 store（AD-13）。若你的应用只需"客户端拿到 Apple/Google/微信令牌，后端验签换取本地身份"，可以完全不装配 store，也不需要读本文余下部分。

## 何时需要持久化

需要：以完整 OIDC 授权服务器形态部署——对外暴露 `/connect/authorize`、`/connect/token` 端点，服务第三方 client，或需要跨应用 SSO、Web 授权码流、服务端会话。

不需要：仅使用外部 IdP 验签能力（见上）。此时 wicketserver 的 quickstart 装配形态即可参考。

## 分层职责

```
宿主应用
    │
    ├── 提供基础设施句柄（连接池、DSN）
    ├── 执行适配器仓的迁移
    ├── 构造适配器实例 → 注入 ServerConfig
    └── 驱动清理循环（wicket 不自起后台任务）
    │
    ↓
适配器平级仓（如 PostgreSQL 适配器）
    │
    ├── 实现 wicket 的 store 端口
    ├── 自有 migrations（表所有权归适配器仓）
    └── 通过 storagetest 契约套件，暴露 ConformsTo()
    │
    ↓
wicket 主模块
    │
    ├── 定义端口接口与契约语义
    ├── 提供内存默认实现（开发用）
    └── 提供 storagetest 契约套件
```

三条边界规则：

- **wicket 主模块零数据库依赖**（AD-2）。持久化实现一律在平级仓，这样只用验签能力的宿主不会继承 Postgres 驱动。
- **宿主不实现 store**（AD-7）。现有适配器不敷使用时，向适配器仓贡献或新建适配器仓，而不是在宿主里写一份。
- **表所有权归适配器仓**。迁移文件随适配器分发，宿主只负责按序执行。

## 宿主装配

### 注入 store

每个 store 端口都有 `ServerConfig` 注入缝，未注入则回退内存实现：

```go
cfg := di.NewServerConfig()

cfg.SetAuthorizationCodeStore(pgadapter.NewAuthorizationCodeStore(pool))
cfg.SetRefreshTokenStore(pgadapter.NewRefreshTokenStore(pool))
cfg.SetReferenceTokenStore(pgadapter.NewReferenceTokenStore(pool))
cfg.SetUserConsentStore(pgadapter.NewUserConsentStore(pool))
cfg.SetPersistedGrantStore(pgadapter.NewPersistedGrantStore(pool))
cfg.SetDeviceFlowStore(pgadapter.NewDeviceFlowStore(pool))
cfg.SetBackchannelAuthenticationRequestStore(pgadapter.NewBackchannelAuthenticationRequestStore(pool))
cfg.SetSessionStore(pgadapter.NewSessionStore(pool))
cfg.SetKeyRecordStore(pgadapter.NewKeyRecordStore(pool))
```

### 禁止混合注入

生产装配下**未注入的 store 应启动即失败**，而不是静默回退内存（AD-4）。混合注入会造出一个多副本下必然失败的系统：授权码在节点 1 的内存里，token 请求打到节点 2 就查不到，用户看到随机的登录失败。

开发模式下若确实要用内存实现，须显式声明：

```go
// 仅开发环境 —— 生产装配省略此调用，未注入的 store 会导致启动失败
cfg.AllowInMemoryFallback()
```

### 可选缝：authorization parameters message store 与 client store

`storeSeams()` 中的每条缝都带类别：`AuthorizationParametersMessageStore` 与 `ClientStore` 两条为**可选缝**，client registration store 一条与 PAR 的两条（pushed authorization request store、pushed authorization data protection）为**特性条件必需缝**（见下文「注入可写 client 注册存储」「注入 PAR 存储与 PAR 数据保护」），其余十条为必需缝。可选缝未注入时 `Freeze()` 不失败，也不需要 `AllowInMemoryFallback()`；配置了 logger 时 `Freeze()` 为每条未注入的可选缝记一条 WARN（只记一次，不随解析反复输出）：

- 未注入 `AuthorizationParametersMessageStore`：不在服务端保存授权参数。
- 未注入 `ClientStore`：client 来自 `SetClients` / `SetClientsProvider` 的静态列表，由内存实现提供。经 `SetClientRegistrationStore` 注入的值同时填充这条缝，此时不记 WARN。

### 注入 client store

client 默认经 `SetClients` 静态列表喂入。需要运行期增删 client（如存数据库）时，改用注入缝：

```go
cfg.SetClientStore(pgadapter.NewClientStore(pool))
```

约束：

- **与 `SetClients` / `SetClientsProvider` 互斥。** 同时设置时 `Freeze()` panic，信息点名 client store 与 `SetClients`；不设静默优先级。
- **注入值须同时实现 `storage.ClientOriginLookup`**（`FindClientsByAllowedOrigin(ctx, origin)`：按 origin 精确匹配 `AllowedCorsOrigins`，不过滤 `Enabled`、不做配置校验，无命中返回空切片与 nil）。CORS 判定经它查询，与 client 读路径同源；未实现时 `Freeze()` panic。注入路径下，命中的 client 须 `Enabled` 且通过配置校验才放行 origin；查询出错则拒绝该 origin 并记日志。静态列表路径的 CORS 匹配结果不变。
- **读路径恒包 `ValidatingClientStore`。** 容器解析 `storage.ClientStore` 得到包着注入值的配置校验装饰器，注入值与静态列表两条路径一致。
- 注入值的生命周期归宿主：容器不关闭它。

### 注入可写 client 注册存储

动态客户端注册这类特性需要一个可写的 client 端口 `storage.ClientRegistrationStore`。它内嵌 `ClientStore`，读与写落在同一个值上，避免「注册成功却查不到」：

```go
cfg.SetClientRegistrationStore(pgadapter.NewClientRegistrationStore(pool))
```

端口方法：

| 方法 | 语义 |
|------|------|
| `RegisterClient(ctx, *models.ClientRegistration) (int, error)` | insert-only，返回修订号 1；client id 已存在或曾被删除（墓碑）返回 `ErrDuplicateHandle`，原记录不变 |
| `FindClientRegistration(ctx, clientId)` | 返回注册记录；缺失（含已删除）返回 `ErrNotFound` |
| `UpdateClientRegistration(ctx, *models.ClientRegistration, expectedRevision) (int, error)` | 修订号与存储值一致才替换，返回提交后的修订号（期望值 +1）；不一致返回 `ErrVersionConflict` 且记录不变；缺失返回 `ErrNotFound` |
| `RemoveClientRegistration(ctx, clientId, expectedRevision)` | 修订号一致才删除并留墓碑；冲突与缺失同上 |
| `FindClientById(ctx, clientId)` | 返回已注册记录中的 client，供既有读路径使用 |
| `FindClientsByAllowedOrigin(ctx, origin)`（`storage.ClientOriginLookup`，注入值必须实现） | 返回 `AllowedCorsOrigins` 精确命中 origin 的已注册 client，不过滤 `Enabled`；更新后按新 origin 命中，已删除者不返回；无命中返回空切片与 nil |

- **修订号由 store 分配。** 入参记录的 `Revision` 被忽略；冲突时调用方重新加载后重试，store 不自行解决冲突。
- **墓碑永久保留。** 已删除的 client id 不会被重新注册，防止已删 client 同名复活后接手它签发过的凭证。
- **不提供** 按注册访问令牌摘要查找、无过滤条件的全量枚举与 `RemoveExpired`；记录不带 issuer 字段。
- **记录类型** `models.ClientRegistration`：`Client`、`Revision`、`RegistrationAccessTokenDigest`、`RegistrationTime`。
- **client 以不透明字节落盘。** 适配器用 `storage.EncodeClient` 序列化 `*models.Client`（带版本号的封套，含 `AllowedGrantTypes`），用 `storage.DecodeClient` 还原；未知版本、损坏输入返回错误，不返回半成品 client。适配器只把字节与可见字段（client id、修订号、摘要、注册时间）入库。codec 按原样编码 `Secret.Value`，不做哈希或保护：调用方必须在 client 中存放 secret 的哈希，不得存明文。

注入约束：

- **注入值须同时实现 `storage.ClientOriginLookup`**，否则 `Freeze()` panic。该值同时充当 client store 缝：容器解析 `storage.ClientStore` 得到包着它的 `ValidatingClientStore`，CORS 判定也经它的 origin 查询（命中的 client 须 `Enabled` 且通过配置校验）。
- **与 `SetClientStore`、`SetClients` / `SetClientsProvider` 互斥。** 并用时 `Freeze()` panic，信息点名两者；不设静默优先级。
- **特性条件必需。** 依赖该端口的特性启用后，未注入即 `Freeze()` panic，`AllowInMemoryFallback()` 不豁免，也没有逐缝回退声明；开发环境需要内存实现时显式注入 `memory.NewMemoryClientRegistrationStore()`。没有依赖特性时该缝不校验，任何代码路径都不会取用可写端口。本版本尚无依赖特性，现有装配行为不变。
- 注入值的生命周期归宿主：容器不关闭它。

适配器用 `storagetest.RunClientRegistrationStoreSuite` 验证合规性（见下文「校验适配器合规性」）。

`ClientStore.FindClientById` 的错误语义：

| 情形 | 返回 |
|------|------|
| client 不存在 | `storage.ErrNotFound`（不得返回 `(nil, nil)`；装饰器也会把 `(nil, nil)` 改写为 `ErrNotFound`） |
| 记录存在但配置校验失败（含依赖未启用的特性） | 装饰器返回包 `storage.ErrInvalidClientConfiguration` 的错误（带 clientId 与校验信息），并记 Error 日志 |
| 基础设施故障 | 原样返回该错误（勿包成 `ErrNotFound`） |

### 注入 PAR 存储与 PAR 数据保护

推送授权请求（PAR，RFC 9126）需要两条缝：保存推送参数的存储端口 `storage.PushedAuthorizationRequestStore`，以及只作用于 PAR 载荷的数据保护缝。

```go
cfg.SetPushedAuthorizationRequestStore(pgadapter.NewPushedAuthorizationRequestStore(pool))
cfg.SetPushedAuthorizationDataProtectionProvider(hostProtectionProvider) // 真正加密/认证的实现
cfg.EnablePushedAuthorizationRequests(pushedauth.Options{RequestUriLifetime: 90 * time.Second})
```

`SetPushedAuthorizationRequestStoreProvider(func() storage.PushedAuthorizationRequestStore)` 为 provider 形态：`Freeze()` 不调用 provider，只检查是否已设置；provider 在特性首次取用存储时调用一次，届时返回 nil 即按未注入报错。

**句柄与键。** 发给 client 的 `request_uri` 形如 `urn:ietf:params:oauth:request_uri:<随机串>`（前缀常量 `storage.PushedAuthorizationRequestURIPrefix`），由 `storage.NewPushedAuthorizationRequestURI()` 生成：前缀 + `crypto/rand` 32 字节的 RawURL base64；随机源失败返回 `("", err)`。store 从不见原始 URN，只见 `storage.PushedAuthorizationRequestKey(requestURI)` 求得的键——写入方与解析方的唯一入口，返回 `base64.RawURLEncoding(sha256(完整 URN))`，恒 43 字符、字符集 `[A-Za-z0-9_-]`；无前缀或前缀后为空返回 `storage.ErrInvalidRequestURI`。store 不生成句柄。

端口方法：

| 方法 | 语义 |
|------|------|
| `StorePushedAuthorizationRequest(ctx, key, *models.PushedAuthorizationRequest)` | insert-only；键已存在返回 `ErrDuplicateHandle`，原记录不变 |
| `GetPushedAuthorizationRequest(ctx, key)` | 只读取用，不删除；返回独立副本；缺失返回 `ErrNotFound` |
| `TakePushedAuthorizationRequest(ctx, key)` | 原子取出：命中即删除并返回独立副本；同一键的并发取出恰一个成功，其余得 `ErrNotFound` |
| `RemoveExpired(ctx, cutoff) (int, error)` | 只回收 `RetentionExpiration` 严格早于 cutoff 的记录，返回计数 |

- **记录类型** `models.PushedAuthorizationRequest`：可见字段 `ClientId`、`CreationTime`、`EntryExpiration`、`RetentionExpiration`，以及不透明的 `Payload`。不带 issuer 字段。
- **两种时限。** `EntryExpiration` 是 `request_uri` 作为入口的有效期截止，由核心判定；`RetentionExpiration` = 入口有效期 + 交互往返（登录、同意）宽限，是回收的唯一依据。入口期已过但保留期未过的记录不得回收。读与取出都不判过期。
- **不提供** 按 client 或全量枚举，也没有存储缝的回退声明。
- **载荷经 PAR 数据保护。** 核心用 `storage.ProtectPushedAuthorizationParameters(protector, params)` 把参数编码成版本容器（`Version`=1、`DataProtected`=true、保护后的字节），用 `storage.UnprotectPushedAuthorizationParameters` 还原；nil protector、未知版本、未标记保护、损坏字节或保护器拒绝一律报错，不返回半成品参数。适配器只把字节与可见字段入库。

PAR 数据保护缝：

- **保护器固定 purpose。** 只经 `provider.Create(storage.PushedAuthorizationRequestPurpose)`（`"wicket.PushedAuthorizationRequest"`）取得，只用于 PAR 载荷与 authorize 签发的进入回执（二者靠内容中的种类标记区分）。
- **拒绝默认实现。** 默认的 `services/impl.DataProtectionProvider` 只做 base64url 编码，注入到这条缝时 `Freeze()` 必 panic（无论 PAR 是否启用），信息点名该缝。
- **无回退。** 这条缝没有任何回退声明。
- **全局绑定不变。** 容器里的 `dp.DataProtectionProvider` 绑定照旧是默认实现，key management 私钥记录与 message cookie 继续用它；PAR 缝不进容器，也不影响它们。

注入约束：

- **特性条件必需。** PAR 启用后，两条缝任一未注入即 `Freeze()` panic，信息点名缺失的缝，`AllowInMemoryFallback()` 不豁免；开发环境需要内存存储时显式注入 `memory.NewMemoryPushedAuthorizationRequestStore()`。PAR 未启用时两条缝不校验、不记 WARN，任何代码路径都取不到端口或保护器。
- **启用开关。** 以 `cfg.EnablePushedAuthorizationRequests(pushedauth.Options{...})` 启用（`Freeze()` 之前调用，见 [API 端点 · 推送授权请求](./api-contracts.md#推送授权请求par)），`cfg.PushedAuthorizationRequestsEnabled()` 查询。这是唯一开关：未调用时两条缝不参与校验，端点、discovery 宣告与 authorize 的 PAR 解析都不存在。
- **回收由宿主驱动。** 核心不清理 PAR 记录：被消费的记录由原子取出删除，过期未用的记录留在存储中，直到宿主定期调用 `RemoveExpired(ctx, cutoff)`（按 `RetentionExpiration` 回收，不会删除仍在交互往返中的记录）。
- 注入值的生命周期归宿主：容器不关闭它。

适配器用 `storagetest.RunPushedAuthorizationRequestStoreSuite` 验证合规性（见下文「校验适配器合规性」）。

### client 存在性闸门

client 被删除、禁用或配置失效后，它已签发的凭证随之失效；client store 故障则表现为服务端错误，而不是"凭证无效"。所有凭证兑换与内省路径对 client 加载做三分处置：`ErrNotFound` / `ErrInvalidClientConfiguration` → 无效凭证；其他错误 → 5xx。

| 路径 | client 已不可用 | client store 故障 |
|------|----------------|------------------|
| token 端点客户端认证（共享密钥、`private_key_jwt`、mTLS 三个认证器）：授权码、refresh、device code、CIBA、client_credentials、password 兑换都先经此重新加载 client | 400 `invalid_client` | 500，固定体 `Internal Server Error`，不写 `invalid_client` / `invalid_grant` |
| device authorization、CIBA 发起、revocation 端点（共用上述认证器） | 各端点既有 `invalid_client` 应答 | 500 |
| 内省：JWT 的 `client_id` 与 reference token 的 `ClientId` | 200 `{"active":false}` | 5xx |
| userinfo：同上 | 既有 `invalid_token` 应答 | 5xx |
| end_session 的 `id_token_hint`（identity token 校验） | 既有无效 hint 处置 | 5xx |

令牌响应生成阶段在认证成功之后同一请求内会再次加载 client，仅竞态窗口可达，任何错误均为 5xx，保持不动。

**离线校验的外部资源服务器不受此闸门约束：** 资源服务器若自行用公开密钥验签 JWT access token 而不调用内省端点，则 client 删除后它仍会接受该 JWT，直到 `exp` 过期为止。需要及时失效时，缩短 access token 生命周期，或改用 reference token / 内省。

### 驱动清理

wicket **不自起后台 goroutine**（AD-12），过期数据的清理由宿主按自身调度驱动：逐个调用自己注入的 store 实例的回收入口（`RemoveExpired`，会话 store 为 `DeleteExpired`）。容器不提供统一的清理入口，store 实例从宿主自己装配时持有的变量取得：

```go
// 宿主装配时注入的实例，例如 cfg.SetRefreshTokenStore(refreshTokens)。
type expiredRemover interface {
    RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}
removers := map[string]expiredRemover{
    "refresh_tokens":      refreshTokens,
    "reference_tokens":    referenceTokens,
    "authorization_codes": authorizationCodes,
    "persisted_grants":    persistedGrants,
    "user_consents":       userConsents,
    "device_flow":         deviceFlowCodes,
    "backchannel":         backchannelRequests,
}

ticker := time.NewTicker(10 * time.Minute)
defer ticker.Stop()
for {
    select {
    case <-ticker.C:
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        now := time.Now()
        for name, store := range removers {
            if _, err := store.RemoveExpired(ctx, now); err != nil {
                logger.Error("cleanup failed", "store", name, "err", err)
            }
        }
        // cfg.SetSessionStore(sessions) 注入的服务端会话 store
        if _, err := sessions.DeleteExpired(ctx, now); err != nil {
            logger.Error("cleanup failed", "store", "sessions", "err", err)
        }
        cancel()
    case <-shutdown:
        return
    }
}
```

只列出宿主实际注入的 store；启用 PAR、DPoP 或 `private_key_jwt` 时，PAR 存储与重放登记（`replay.Registry`）同样按此回收。

清理只回收空间，**不承担正确性**——过期判定始终在 wicket 核心侧完成（AD-3 要素 6）。

reference access token 也在须回收之列：client 配置 `AccessTokenType=Reference` 时，令牌端点与授权端点每签发一个 access token（含每次 refresh 换发）就向 `ReferenceTokenStore` 写入一条记录。被撤销的记录会删除；过期而未被撤销的记录 wicket 不回收，须由宿主调用该 store 的 `RemoveExpired`，否则 store 持续增长（in-memory 回退表现为进程内存增长）。

为 Reference client 自备 store 时另有两点：

- `RefreshTokenStore` 须完整往返 refresh token 内保存的 access token 模型，至少包括 `ClientId` 与 `AccessTokenType`。refresh 换发默认复用该模型：丢失 `AccessTokenType` 会使换发静默签发 JWT，丢失 `ClientId` 会使换发失败。契约测试套件目前不检查这一点。
- `ReferenceTokenStore.StoreReferenceToken` 失败时，wicket 不把 store 的错误文本写入响应或自身日志（只保留错误身份，可用 `errors.Is` / `errors.As` 取得），故障原因须由 store 在自己一侧记录；句柄是凭据，store 的错误文本与日志不应包含句柄或记录内容。

启用 DPoP 时另有一点，适用于任何自备的 `RefreshTokenStore`：须持久化并往返 `RefreshToken.DPoPKeyThumbprint`（DPoP proof 密钥指纹，见 [API 契约 · DPoP](./api-contracts.md#dpoprfc-9449)）。public client 带 DPoP proof 获得的 refresh token 靠这个字段绑定到 proof 密钥；适配器丢失它，绑定即静默失效，持有被窃 refresh token 的一方无需私钥就能兑换。契约测试套件目前不检查这一点，自备适配器须自行确认。同理，自备 client store 须往返 `Client.RequireDPoP`，丢失它会使按 client 强制 DPoP 静默失效。自备 `AuthorizationCodeStore` 须往返 `AuthorizationCode.DPoPKeyThumbprint`（authorize 请求 `dpop_jkt` 预绑定的指纹，见 [API 契约 · `dpop_jkt` 预绑定](./api-contracts.md#dpop_jkt-预绑定rfc-9449-10)）；丢失它，预绑定静默失效，截获授权码的一方可用自己的密钥兑换。契约测试套件同样不检查这一字段。DPoP 服务端 nonce 无状态，不需要任何存储。

自备的 `RefreshTokenStore` 还须在 `UpdateRefreshToken` 时写回 `RefreshToken.CreationTime` 与 `RefreshToken.Lifetime`：核心在首次成功兑换时为没有创建时刻的旧记录补记这两个字段，滑动方式下每次兑换都改写 `Lifetime`，两者都经更新写回（见下文旧记录迁移一节）。`storagetest` 以 MAY 级用例 `LifetimeUpdateRoundTrips`（以 `storagetest.WithMay(true)` 运行）检查 `UpdateRefreshToken` 写回 `CreationTime` 与 `Lifetime`、`RemoveExpired` 按更新后的值判定；MUST 用例未收紧，`SuiteVersion` 仍为 `2.0.0`。

### 既有 refresh token 记录的迁移

自 v0.6.1 起，refresh token 签发时记下 `CreationTime` 与按 client 配置得出的 `Lifetime`，兑换时由核心判过期（见 [API 契约 · refresh token 寿命](./api-contracts.md#refresh-token-寿命)）。v0.6.1 之前签发的记录 `CreationTime` 为零值、`Lifetime` 为 0（v0.5.0、v0.6.0 中按文档调用 `RemoveExpired` 会删除全部 refresh token，即由此而来）：

- 首次成功兑换时核心会补记：`CreationTime` 取当前时刻，`Lifetime` 按 client 当前配置算出，随本次兑换写回；兑换在请求校验阶段被拒（scope、resource、DPoP 绑定等）时不写回，记录仍为零值。
- 但 `RemoveExpired` 的判定式（`CreationTime + Lifetime` 早于 cutoff）把这类记录一律视为已过期。升级后宿主第一次调用 `RefreshTokenStore.RemoveExpired` 就会删除全部未补记的旧记录，持有者只能重新授权。

不想让旧 token 失效的宿主，在升级后第一次回收之前回填旧记录：`CreationTime` 设为回填时刻（或已知的签发时刻），`Lifetime` 按该记录 client 的配置设置（与签发时的算式一致）：

| client 配置 | `Lifetime` |
|------|------|
| 绝对方式（或滑动方式且 `SlidingRefreshTokenLifetime == 0`），`AbsoluteRefreshTokenLifetime > 0` | `AbsoluteRefreshTokenLifetime` |
| 滑动方式，`SlidingRefreshTokenLifetime > 0` 且 `AbsoluteRefreshTokenLifetime > 0` | `min(SlidingRefreshTokenLifetime, AbsoluteRefreshTokenLifetime)` |
| 滑动方式，`SlidingRefreshTokenLifetime > 0` 且 `AbsoluteRefreshTokenLifetime == 0`（不封顶） | `SlidingRefreshTokenLifetime` |
| 适用的寿命字段都为 0（不限） | `2147483647` |

用 wicket 的接口回填时，读出记录、改这两个字段，再以读到的 `Version` 调 `UpdateRefreshToken`。in-memory store 的记录随进程重启丢失，无需迁移。

外部适配器另须注意：

- 按 `CreationTime + Lifetime` 派生过期列（如 `expires_at`）的实现，回填时须连同派生列一起更新；零值记录派生出的过期时刻在公元 1 年，会被首次回收删除。SQL 实现可以按 `creation_time` 为零值筛出旧行，在一条 `UPDATE` 里同时写 `creation_time`、`lifetime` 与 `expires_at`。
- 滑动方式下每次兑换都会改写 `Lifetime`：`UpdateRefreshToken` 须写回 `CreationTime` 与 `Lifetime`，派生过期列须在更新时重算，不能只在插入时计算。`storagetest` 的 MAY 级用例 `LifetimeUpdateRoundTrips`（以 `storagetest.WithMay(true)` 运行）检查这一点。
- `Lifetime` 最大为 `2147483647` 秒（约 68 年），派生列的时间类型须容得下 `CreationTime` 加上这个值。

### 释放资源

适配器持有的连接池在 `Root.Close()` 路径上释放：

```go
defer root.Close()
```

## PostgreSQL 适配器

`github.com/gonewx/wicket-pg` 是官方 PostgreSQL 适配器：九个 store 端口已全部实现并随发布版本分发，宿主无需阅读适配器源码即可按本节装配。

> **版本注意：** 其 `v0.1.x` 的 `ConformsTo()` 早于契约套件 2.0.0，在适配器仓发布对应 2.0.0 的版本之前，不能通过 wicket v0.5.0 宿主的相等比较（见「校验适配器合规性」）。v0.5.0 的宿主须等适配器仓发布对应版本，或暂留在与其 `ConformsTo()` 相符的 wicket 版本。

### 安装

```bash
GOWORK=off go get github.com/gonewx/wicket-pg@v0.1.1
```

版本号以该仓 release 页的最新已发布版本为准。宿主需 Go 1.27 工具链（见「当前状态与前置条件」）。

### 执行迁移

适配器仓自备迁移（表所有权归适配器仓），宿主在启动序列中调用迁移入口。迁移幂等、不自动触发、不起后台 goroutine（AD-12）：

```go
import (
	"context"

	"github.com/gonewx/wicket-pg/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

pool, err := pgxpool.New(ctx, dsn)
if err != nil {
	// handle error
}

if err := migrations.Up(ctx, pool); err != nil {
	// handle error
}
```

需要回滚时调用 `migrations.Down(ctx, pool)`（回滚全部已应用的迁移版本）。

### 注入 store

九个 store 构造器逐一注入，签名均为 `store.NewXxxStore(pool *pgxpool.Pool, logger *slog.Logger)`。连接池由宿主创建与管理，适配器不创建也不关闭；logger 传 `nil` 时回退 `slog.Default()`：

```go
import (
	"log/slog"

	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket-pg/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool  // host-owned
var logger *slog.Logger // may be nil; falls back to slog.Default()

cfg := di.NewServerConfig()

cfg.SetAuthorizationCodeStore(store.NewAuthorizationCodeStore(pool, logger))
cfg.SetRefreshTokenStore(store.NewRefreshTokenStore(pool, logger))
cfg.SetReferenceTokenStore(store.NewReferenceTokenStore(pool, logger))
cfg.SetUserConsentStore(store.NewUserConsentStore(pool, logger))
cfg.SetPersistedGrantStore(store.NewPersistedGrantStore(pool, logger))
cfg.SetDeviceFlowStore(store.NewDeviceFlowStore(pool, logger))
cfg.SetBackchannelAuthenticationRequestStore(store.NewBackchannelAuthenticationRequestStore(pool, logger))
cfg.SetSessionStore(store.NewSessionStore(pool, logger))
cfg.SetRecordStore(store.NewKeyRecordStore(pool, logger))
```

九个 store 均暴露 `ConformsTo()` 版本凭证，可按下节方式校验；但对 wicket v0.5.0 而言，`v0.1.x` 的凭证不等于 `storagetest.SuiteVersion`（见本节开头的版本注意）。过期数据的回收由宿主驱动（store 暴露显式回收入口，如 `RemoveExpired` / `DeleteExpired`），wicket 不自起后台任务（AD-12）。

更完整的快速开始见适配器仓 README（`github.com/gonewx/wicket-pg`），表结构与索引设计见该仓的 schema 设计记录（`docs/schema-design-record.md`）。

## 校验适配器合规性

适配器必须通过 wicket 的契约测试套件，并暴露版本凭证（AD-6）。装配时校验：

```go
if got := adapter.ConformsTo(); got != storagetest.SuiteVersion {
    log.Fatalf("适配器契约版本不匹配: 适配器=%s, wicket 要求=%s", got, storagetest.SuiteVersion)
}
```

client 注册存储的契约套件入口为 `storagetest.RunClientRegistrationStoreSuite(t, newStore, storagetest.WithMay(true))`，覆盖墓碑、修订号冲突与重试、并发注册与并发更新恰一次成功，以及 origin 查询精确匹配。

PAR 存储的契约套件入口为 `storagetest.RunPushedAuthorizationRequestStoreSuite(t, newStore, storagetest.WithMay(true))`，所有键经 `storage.PushedAuthorizationRequestKey` 求得，覆盖键形态、insert-only、只读取用不消费、并发取出恰一次、过期仍可读可取，以及按 `RetentionExpiration` 回收（`MUST/RemoveExpiredKeepsRecordsInRoundTrip`：入口期已过、保留期未过的记录不得回收）。

没有 `ConformsTo()` 的实现不是合规适配器——它可能连契约套件都没跑过，或者 `t.Skip()` 掉了一半用例。

## 存储契约要点

宿主一般不需要关心这些细节，但理解它们有助于判断适配器质量、以及排查换介质后的行为差异。完整定义见 AD-3。

**"不存在"与"故障"必须可区分。** store 在记录不存在时返回 `ErrNotFound` 哨兵，绝不返回 `(nil, nil)`。这条很要紧：若二者混为一谈，一次数据库网络抖动会被当成"凭证无效"，用户看到登录失败而日志里没有任何告警。client 读路径据此做存在性闸门，见上文「client 存在性闸门」。

**写入默认 insert-only。** 句柄碰撞返回 `ErrDuplicateHandle`。refresh token 轮换的重放防线依赖这个语义——若某个适配器实现成 upsert（如 Redis 的 `SET` 天然覆盖），防线会静默失效。

**并发更新需要版本号。** 读-改-写类更新携带 `expectedVersion`，冲突返回 `ErrVersionConflict`。宿主侧一般由 wicket 核心处理重试，不需要自己写循环。

**超时由调用方决定。** 每个 store 方法首参为 `context.Context`，适配器不得自设超时覆盖。你在 HTTP handler 里设的 deadline 会一路传到数据库查询。

**过期判定在核心侧。** 适配器**不得**在查询里加 `expires_at > now()` 之类的过滤。理由是集群里数据库时钟与应用节点时钟会漂移，两处判定得出不同结论；统一在核心侧用注入的 `Clock` 判定才可控。

**一次性兑换靠原子取出。** 授权码兑换走 `AuthorizationCodeStore.TakeAuthorizationCode`：命中即删除并返回独立副本，未命中返回 `ErrNotFound`；同一句柄的并发取出恰一个成功，其余均得 `ErrNotFound`。适配器须在单条原子操作内完成"查找 + 删除"（如 `DELETE ... RETURNING`、Redis `GETDEL`），不得拆成先读后删两步。介质没有这类原语时（如 MySQL、Redis < 6.2），在事务内先 `SELECT ... FOR UPDATE` 再 `DELETE`，以影响行数 == 1 判定命中（Redis 则用 Lua 脚本完成查找加删除）；READ COMMITTED 下普通的先读后删不是原子的。取出不判过期，过期码照样取出（核心随后判过期并拒绝，码已作废）。token 端点先取出再做 client 绑定、过期、redirect_uri、PKCE 等全部授权码校验，所以校验失败的码也已作废。

**删除不存在的句柄返回 nil。** 全部单句柄删除（`RemoveAuthorizationCode`、`RemoveRefreshToken`、`RemoveReferenceToken`、`RemoveUserConsent`、`PersistedGrantStore.Remove`、`DeviceFlowStore.RemoveByDeviceCode`、`RemoveBackchannelAuthenticationRequest`）对不存在或已删除的句柄必须返回 nil；`RemoveReferenceTokens(subjectId, clientId)` 零匹配同样返回 nil。并发重复撤销时，后到的请求会删一个已不存在的句柄，若适配器报错，撤销端点会以服务器错误应答。

**按 client、按会话批量删除。** 以下方法返回删除条数：

| 端口 | 按 `client_id` | 按会话标识 |
|------|---------------|-----------|
| `AuthorizationCodeStore` | `RemoveAuthorizationCodesByClient` | `RemoveAuthorizationCodesBySession`（`SessionId` 字段） |
| `RefreshTokenStore` | `RemoveRefreshTokensByClient` | `RemoveRefreshTokensBySession`（`SessionId` 字段） |
| `ReferenceTokenStore` | `RemoveReferenceTokensByClient` | `RemoveReferenceTokensBySession`（`Token.SessionId()`，即 `sid` claim） |
| `UserConsentStore` | `RemoveUserConsentsByClient` | — |

删零条返回 `(0, nil)`，不算错误；参数为空串时不匹配任何记录、返回 `(0, nil)`，不得清掉"字段为空"的记录。不支持事务的介质可以部分完成，但必须返回错误。适配器须把 `client_id` 与会话标识存成可见、可索引的列，不得只藏在序列化载荷里——否则批量删除只能全表扫描并逐条反序列化。`PersistedGrantStore` 继续用 `RemoveAll` 的 `ClientId` / `SessionId` 过滤。

## 升级到契约套件 2.0.0（v0.5.0）

v0.5.0 把一批端口变更合在一个大版本里发出：`storagetest`、`sessiontest`、`keymgmttest` 三套 lockstep 由 `1.1.0` 升至 `2.0.0`。判定依据是本批改了既有接口（四个 store 端口新增方法；`validators.AuthorizeRequestValidator.Validate` 加参数），并新增了收紧既有方法契约的 MUST 用例（单句柄删除对缺失返回 nil），属大版本；`sessiontest` 与 `keymgmttest` 没有用例变化，只因 lockstep 同步，宿主仍只比一个数。wicket 本身不检查 `ConformsTo()`；按相等比较 `ConformsTo()` 与 `SuiteVersion` 的宿主，会在自己的装配校验中拒绝仍返回 `1.1.0` 的适配器。

适配器逐项清单：

1. **既有端口的新增方法。** `AuthorizationCodeStore.TakeAuthorizationCode`（原子取出，见「存储契约要点」）；`RemoveAuthorizationCodesByClient` / `BySession`、`RemoveRefreshTokensByClient` / `BySession`、`RemoveReferenceTokensByClient` / `BySession`、`RemoveUserConsentsByClient`（见「按 client、按会话批量删除」）。
2. **新端口（按需实现）。** 提供 PAR 时实现 `storage.PushedAuthorizationRequestStore`（见「注入 PAR 存储与 PAR 数据保护」）；提供 client 注册时实现 `storage.ClientRegistrationStore` 并同时实现 `storage.ClientOriginLookup`（见「注入可写 client 注册存储」）；提供 client 读取时，注入 `SetClientStore` 的值须实现 `storage.ClientOriginLookup`，且 client 不存在时返回 `storage.ErrNotFound`（不得返回 `(nil, nil)`），基础设施故障原样返回、不包成 `ErrNotFound`（见「注入可写 client 注册存储」节末的 `FindClientById` 错误语义表）。各端口分别跑 `RunPushedAuthorizationRequestStoreSuite` / `RunClientRegistrationStoreSuite`。
3. **单句柄删除对缺失返回 nil。** 全部单句柄删除与 `RemoveReferenceTokens` 零匹配都返回 nil（见「删除不存在的句柄返回 nil」）；之前把缺失报成错误的适配器须改。
4. **可见、可索引字段。** 授权码、refresh token、reference token 的 `client_id` 与会话标识，用户同意的 `client_id`；PAR 记录的 `ClientId` 与三个时间字段；注册记录的 client id、修订号、注册访问令牌摘要与注册时间。载荷（PAR 参数、`*models.Client`）一律只存不透明字节。
5. **键函数。** PAR 记录的键只经 `storage.PushedAuthorizationRequestKey` 求得，适配器不生成、不解析句柄。
6. **`ConformsTo()` 改返回 `2.0.0`。** 通过 2.0.0 套件后，每个 `storage` / `session` / `keymgmt` store 类型都改返回 `2.0.0`。
7. **`replaytest` 不变。** 重放登记适配器继续返回 `replaytest.SuiteVersion`（`1.0.0`），宿主对它单独比较。

宿主侧（不涉及适配器）：client store 缝与 authorization parameters message store 缝为可选缝；PAR 与 client 注册的缝为特性条件必需缝，`AllowInMemoryFallback()` 不豁免；PAR 数据保护缝拒绝默认实现且无回退；`ValidatingClientStore` 对缺失返回 `storage.ErrNotFound`、校验失败返回包 `storage.ErrInvalidClientConfiguration` 的错误；凭证兑换与内省路径据此做存在性闸门。RFC 7592 读时轮换所依赖的「带期望 `Revision` 的更新」语义已在可写 client 端口中交付，轮换本身随后续版本的 RFC 7592 管理端点落地。

## AD-21 约束：为多 issuer 留余地

FR33 的单 issuer 裁决维持不变；本批新端口按以下约束设计，使日后引入 issuer 分区时无须为它们做数据迁移：

- **无全量枚举。** `PushedAuthorizationRequestStore` 与 `ClientRegistrationStore` 都不提供无过滤条件的枚举方法；`ClientOriginLookup` 带 origin 过滤条件，不在此列。适配器不得为方便自行加枚举出口。
- **PAR 句柄全局唯一随机。** `request_uri` 由核心经 `storage.NewPushedAuthorizationRequestURI()` 以 `crypto/rand` 32 字节生成，不用序号或任何可能在不同 issuer 间重复的自然键；store 只见其摘要键。
- **`client_id` 全局唯一随机。** 这条义务随核心签发 `client_id` 的特性（动态客户端注册）落地。当前版本核心不生成 `client_id`，`RegisterClient` 接受调用方给出的 id；碰撞（含墓碑）返回 `ErrDuplicateHandle`。
- **不带 issuer 字段。** `models.PushedAuthorizationRequest` 与 `models.ClientRegistration` 都不携带 issuer 或租户字段，端口方法也不接收这类参数；适配器的 schema 不应预先加入此列。

## 编写适配器

若要为新介质编写适配器，最低要求：

1. **独立仓** `require github.com/gonewx/wicket`，实现所需 store 端口。
2. **通过契约套件** —— 引入 `storage/storagetest`，跑全部 MUST 级用例，容器/夹具自备。
3. **暴露 `ConformsTo()`** 返回所依据的 `storagetest.SuiteVersion`。
4. **自备迁移** —— 表所有权归你的仓。
5. **血缘门禁** —— 移植 wicket 的等效门禁（文件头归属断言、禁上游血缘标注、commit message 扫描）。跨仓不等于免除血缘纪律（AD-14）。
6. **LICENSE / NOTICE / PROVENANCE** —— 新仓属独立实现模块，须自备三件套并留独立设计记录。

**schema 独立设计**（AD-10）：表结构须从 wicket 端口的读写访问模式推导——按句柄取用、按 subject 批量吊销、按过期时间清理——而不是逐一映射 `storage/models/*.go` 的字段（那些 model 带上游 Apache 血缘）。留存设计记录说明每张表、每个索引对应哪条端口方法。序列化载荷沿用 `PersistentGrantDataContainer` 的版本容器形态以单列存储。列名的 snake_case 转写属语言惯例，但禁止照搬上游 EntityFramework 的表名、实体划分与列集合。

**日志与凭据**（AD-12）：日志经注入的 `*slog.Logger`，不自建 logger 或写 stdout。**禁止**把令牌值、句柄、密钥、client secret 写入任何级别的日志——只记其存在性与标识符前缀。

## 当前状态与前置条件

本文所述形态的落地依赖一条不可颠倒的顺序链（AD-8）；wicket 首版 `v0.1.0` 已发布，链上其余前置环节均已解除；适配器仓 `github.com/gonewx/wicket-pg` 已发布 `v0.1.x` 并完成 `require wicket` 接入（见上文「PostgreSQL 适配器」节）。

```
godi 建远端托管 → godi 发版 → 进 wicket go.mod → 清 go.work 遗留
  → AD-3 契约修正 + AD-4 注入缝统一 + AD-11 句柄职责收敛
  → storagetest 契约套件 → 血缘证据链核验 → Go 1.27 正式版
  → wicket v0.x 首个 tag → 适配器仓 require wicket
```

已解除的前置：

- `github.com/gonewx/godi` 已发布 `v0.1.0` 并入 `go.mod`；wicket 首个版本 `v0.1.0` 发布后即可被外部 `go get`（需 Go 1.27 工具链）。
- `go.mod` 已切 `go 1.27` 无 rc directive；首个 tag 不携带 rc。
- Go 1.27 正式版已发布，`mise.toml` 工具链 pin 已由 release candidate 切至正式版 `1.27.0`。

**PostgreSQL 适配器已实现并发布。** `github.com/gonewx/wicket-pg`（module `github.com/gonewx/wicket-pg`）为 PostgreSQL 适配器仓，九个 store 实现、schema 与迁移均已落地并发布 `v0.1.x`，表所有权归该仓；快速开始见上文「PostgreSQL 适配器」节与适配器仓 README。其 `v0.1.x` 的 `ConformsTo()` 早于契约套件 2.0.0，在适配器仓发布对应 2.0.0 的版本之前，不能通过 wicket v0.5.0 宿主的相等比较；适配器的跟进属仓外项目。

## 重放登记适配器

重放登记是独立于上文三族的第四个端口：它让一次性标识（客户端断言的 `jti`、DPoP proof 的 `jti`）在有效期内只被接受一次，多副本部署下也成立。端口定义在 `replay` 包，契约套件在 `replay/replaytest`。

```go
type Registry interface {
    Register(ctx context.Context, key string, expiresAt time.Time) error
    RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}
```

- `Register` 是 insert-only 的原子登记：键未登记时返回 nil；已登记且尚未回收时返回 `replay.ErrDuplicateHandle`，已存记录（含过期时刻）原样不变。同一键的并发登记恰有一个成功。空键或零值过期时刻返回 `replay.ErrInvalidArgument`。
- `RemoveExpired` 回收过期时刻**严格早于** `cutoff` 的记录并返回本次回收数；过期时刻等于 `cutoff` 的记录保留。
- 端口没有读取、按键删除、枚举操作，也**不看任何时钟**：已登记而未回收的键，不论其过期时刻是否已过，一律判重复。
- 键由 `replay.Key` 生成（64 个小写十六进制字符的摘要），适配器按字节精确比较，存储中不出现原始 `jti`。`replay.ErrDuplicateHandle` 是 `replay` 包自有的值，与 `storage.ErrDuplicateHandle` 不是同一个；适配器只需 import `replay`。

**当前状态：** 这条注入缝只在依赖它的特性启用时才是必需的。自 v0.4.0 起，`private_key_jwt` 客户端认证（`ServerConfig.EnablePrivateKeyJwt`）依赖它；DPoP（`ServerConfig.EnableDPoP`）同样依赖它。任一启用后未注入即 `Freeze()` 失败。未启用任何依赖特性时它不参与 `Freeze()` 校验，wicket 也不会读取它，现有装配无须改动。

### 注入与回退

```go
cfg.SetReplayRegistry(registry) // 或 cfg.SetReplayRegistryProvider(func() replay.Registry { ... })
```

依赖它的特性启用后，未注入重放登记的装配在 `Freeze()` 失败。**全局的 `AllowInMemoryFallback()` 不豁免这条缝**；要用内存实现，须针对它单独声明：

```go
// 仅单进程部署或开发环境
cfg.AllowInMemoryReplayRegistryFallback()
```

内存实现 `replay.MemoryRegistry` 只在单个进程内正确：各副本各有一份记录，在一个副本上用过的标识到另一个副本还能再用一次。落到内存实现时 wicket 记一条 WARN。

### 单独比较 `SuiteVersion`

`replaytest.SuiteVersion` 自 `1.0.0` 起**单独计版本**，不随 `storagetest` / `sessiontest` / `keymgmttest` 三套一起步进，它们的版本也不因它而变。重放登记适配器是独立的 store 类型（不与其他端口的 store 合为一个类型），暴露 `ConformsTo()` 返回它验证所依据的 `replaytest.SuiteVersion`。宿主对它单独做相等比较，不与 `storagetest.SuiteVersion` 比：

```go
if got := registry.ConformsTo(); got != replaytest.SuiteVersion {
    log.Fatalf("重放登记适配器契约版本不匹配: 适配器=%s, wicket 要求=%s", got, replaytest.SuiteVersion)
}
```

适配器在自己的测试里备好介质后调用 `replaytest.RunRegistrySuite(t, newRegistry)`，`newRegistry` 每次返回一个全新且空的登记。MUST 级用例恒运行；`replaytest.WithMay(true)` 另加 MAY 级用例。套件不看钟也不等待，时刻全部取自固定常量：基准为 `2100-01-01T00:00:00Z`、前后各不超过十小时，另有一个只用于「已过期但未回收」用例的 `2001-01-01T00:00:00Z`；所以介质须能存储并比较这两处的时刻。

通过套件**不等于**满足全部契约，有两条硬性要求套件钉不住：

- **原子性。** 并发用例对"先查后写"的检出力取决于查与写之间的窗口：窗口是一次网络或磁盘往返时能稳定暴露，窗口只有纳秒级时几乎检不出。适配器不得以该用例通过作为原子性的证明，须由介质的原子原语（唯一约束上的插入、条件写入等）保证。
- **原生 TTL。** 套件无法检出介质原生 TTL，通过套件不构成未使用 TTL 的证明（见下节）。

### 介质不得淘汰未过期记录

这是**宿主的部署责任**。记录只能经 `RemoveExpired` 回收，由宿主按自身调度驱动；适配器不得使用介质原生 TTL 或淘汰策略，也不得在 `Register` 里顺手回收或自起后台任务（AD-12）。

理由在于失败的方向：未回收的键一律判重复，所以回收得晚只是多占空间，不影响正确性；而介质若在记录到期前把它丢掉（内存上限触发的淘汰、原生过期、未持久化时的重启），被丢掉的标识就会被再次接受，重放防护在无任何报错的情况下失效。因此介质须配置为**不淘汰**，适配器文档须写明它所要求的介质配置，宿主部署时须照此核对。

介质的时间精度粗于纳秒时，存储过期时刻只许向后取整（变晚），不许向前截断。

## 相关文档

- ARCHITECTURE-SPINE — 权威架构约束（开发工作区 `_bmad-output/` 下，不随发布产物分发）
- [架构文档](./architecture.md) — 整体架构
- [外部认证提供者配置指南](./external-providers-guide.md) — 无状态验签路径（不需要 store）
- [开发指南](./development-guide.md) — 构建与测试
- [PROVENANCE.md](../PROVENANCE.md) — 血缘声明与桶归属
