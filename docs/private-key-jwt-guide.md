# private_key_jwt 客户端认证接入指南

> 状态：**已落地，默认关闭**。本特性让机密 client 用自己私钥签名的 JWT 断言（RFC 7523 / RFC 7521）代替共享 secret 完成客户端认证。未启用时，wicket 的认证方式列表、discovery 文档与既有 client 的行为都与此前相同。

## 概述

| 项 | 内容 |
| --- | --- |
| 启用入口 | `ServerConfig.EnablePrivateKeyJwt(clientassertion.Options)`，须在 `Freeze()` 之前调用 |
| 覆盖端点 | token、revocation、backchannel authentication（CIBA）、device authorization、introspection |
| 请求参数 | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` 与 `client_assertion=<JWS Compact>`；`client_id` 可选，出现时必须与断言指向同一个 client |
| 必需依赖 | 重放登记端口 `replay.Registry`（一旦启用即成为必需缝） |
| 失败响应 | 各端点既有的 `invalid_client` 响应，不带描述；登记端口故障为 500 固定响应体 |

## 启用步骤与时序

根容器在 `di.NewRoot()` 内就构造好全部单例，因此启用声明一定发生在根容器建好**之后**、`Freeze()` **之前**：

```go
root, err := di.NewRoot()
if err != nil {
    return err
}
cfg := root.ServerConfig()

cfg.SetReplayRegistry(registry)                       // 生产装配：注入多副本共享的登记适配器
cfg.EnablePrivateKeyJwt(clientassertion.Options{})    // 零值字段取默认值
cfg.Freeze()                                          // 之后才开始服务请求
```

- `Freeze()` 之后再调用 `EnablePrivateKeyJwt` 会 panic。
- `Options` 不合法时 `Freeze()` 以 `private_key_jwt options invalid: ` 开头的文本 panic。
- 在 `Freeze()` 之前解析 handler 或 `storage.ClientStore` 属于不受支持的用法：它们按解析当时的声明取值，之后的启用声明不会补偿。

### 登记端口是必需的

断言的 `jti` 在有效期内只接受一次，这份状态由 `replay.Registry` 承载。启用本特性后：

- 没有调用 `SetReplayRegistry` / `SetReplayRegistryProvider`，也没有调用 `AllowInMemoryReplayRegistryFallback()` → `Freeze()` panic。`AllowInMemoryFallback()` 不覆盖这条缝。
- `AllowInMemoryReplayRegistryFallback()` 接受进程内登记并在首次使用时记一条 WARN。进程内登记只在单进程内正确；多副本部署必须注入共享的适配器，否则同一断言可以在每个副本各用一次。
- 同一断言在所有端点之间也只能用一次：登记键只由用途、client 标识与 `jti` 生成，不含端点。

### 回收过期记录

登记端口从不自行过期，过期记录由宿主驱动回收。从容器解析 `replay.Registry` 得到的是一个惰性包装，无论底层是注入的适配器还是回退的进程内登记，都可以对它调用：

```go
registry := godi.GetRequired[replay.Registry](root)
removed, err := registry.RemoveExpired(ctx, time.Now())
```

特性未启用时不要调用它的方法：包装会 panic，说明没有任何依赖该缝的特性被启用。`root.Close()` 会关闭已物化的登记适配器（若它实现了 `io.Closer`）。

## client 元数据

`storage/models.Client` 内嵌 `ClientAuthenticationMetadata`，三个字段：

| 字段 | 含义 |
| --- | --- |
| `TokenEndpointAuthMethod` | `""` 表示未登记（沿用共享 secret 或公开 client 的既有行为）；`"private_key_jwt"` 表示该 client 只能用断言认证 |
| `Jwks` | 内联 JWK Set 文档（JSON 文本） |
| `JwksUri` | 预登记的 JWK Set 地址 |

规则：

- `Jwks` 与 `JwksUri` 必须恰好登记一个；同时登记或都不登记，认证一律失败。
- 登记为 `private_key_jwt` 的 client 出示 `client_secret`（表单或 Basic）或不出示凭据，一律 `invalid_client`；它的 `RequireClientSecret`、`ClientSecrets` 对认证不起作用。
- 未登记该方式的 client 带断言参数请求，同样 `invalid_client`。
- 同一请求同时带断言与共享 secret（多种认证机制并存）→ `invalid_client`。
- **未启用特性的装配中**，登记为 `private_key_jwt` 的 client 被 client 配置校验器判为配置无效，从 `storage.ClientStore` 加载不出来，任何端点都拒绝它；不存在静默降级为共享 secret 或公开 client 的路径。
- `TokenEndpointAuthMethod` 取这两个值之外的任何值，同样被判为配置无效。

### introspection 端点

introspection 认证的主体是 API 资源而不是 client。API 资源以其名称作断言的 `iss` 与 `sub`，公钥取自 `ApiSecrets` 中 `Type` 为 `JWK` 的条目（`Value` 是单个 JWK 或 JWK Set 的 JSON），没有 `jwks_uri`。条目的 `Expiration` 非零且当前时刻不早于它时该条目已过期、被忽略；零值表示永不过期。注意这与共享 secret 条目现行的过期判定方向不同。API 资源可以同时持有共享 secret 与 JWK 条目，出示哪一种都可以。

## 断言的要求

| 项 | 规则 |
| --- | --- |
| 形式 | JWS Compact（三段），长度不超过 `MaxAssertionBytes` |
| `alg` | 必须在 `SigningAlgorithms` 内；只有非对称算法 `RS256/384/512`、`PS256/384/512`、`ES256/384/512`。`none`、`HS*` 与其他值一律拒绝 |
| 密钥 | `RS*` / `PS*` 配不小于 2048 位的 RSA 公钥；`ES256/384/512` 分别配 P-256 / P-384 / P-521。JWK 带 `use` 且不为 `sig`、或带 `alg` 且与断言头不同，不作候选 |
| `kid` | 有 `kid` 时按 `kid` 选密钥；没有 `kid` 时登记的可用密钥必须恰好一把 |
| 头部其他成员 | `typ` 不参与判定；带 `crit` 拒绝；`jwk`、`jku`、`x5u`、`x5c` 一律忽略，绝不作为密钥来源 |
| `iss`、`sub` | 都必须逐字节等于 client id（introspection 为 API 资源名） |
| `aud` | 见下节 |
| `exp` | 必需；`exp + ClockSkew` 不晚于当前时刻即过期；`exp` 距当前时刻不得超过 `MaxAssertionLifetime` |
| `nbf`、`iat` | 可缺失；`nbf`、`iat` 不得晚于当前时刻加 `ClockSkew`；`iat` 距今不得超过 `MaxAssertionLifetime + ClockSkew` |
| `jti` | 必需，非空，不超过 256 字节；在有效期内只接受一次 |

### `aud` 规则与迁移提示

`aud` 必须以授权服务器的 **issuer 标识**为唯一值（RFC 10070 对 RFC 7523 的修订）：

- 接受：等于 issuer 的字符串；恰含一个元素且该元素等于 issuer 的数组。
- 拒绝：token 端点 URL 或任何其他端点 URL；两个及以上元素的数组（即使每个元素都等于 issuer）；缺失或空数组。
- 比较是逐字节的：不增删末尾斜杠，不折叠大小写。issuer 取自 `IssuerNameService`，与 discovery 文档的 `issuer` 相同。

**迁移提示**：按旧式写法以 token 端点 URL 作 `aud` 的 client 会被拒绝，须改为 issuer 标识。

## `Options` 各项与默认值

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `ClockSkew` | 60s | 时间 claim 的时钟偏差容忍；上限 10min |
| `MaxAssertionLifetime` | 5min | `exp` 距当前时刻的上限；上限 1h |
| `SigningAlgorithms` | 全部九种 | 接受的签名算法，须为上表九种的子集且不重复；同时是 discovery 宣告的值 |
| `MaxAssertionBytes` | 16384 | 断言长度上限 |
| `JwksFetchTimeout` | 5s | 拉取 `jwks_uri` 的超时 |
| `MaxJwksResponseBytes` | 262144 | `jwks_uri` 响应体上限 |
| `JwksCacheLifetime` | 1h | 已拉取密钥集合的缓存寿命 |
| `JwksMinRefreshInterval` | 60s | 对同一 `jwks_uri` 两次出站请求的最小间隔 |
| `HTTPClient` | nil | 只采用它的 `Transport`；见下节 |
| `AllowInsecureJwksUri` | false | 为真时允许 `http` 的 `jwks_uri`（仅用于开发） |

任何负值、`none` / `HS*` / 未知算法、重复算法、超过上限的 `ClockSkew` 与 `MaxAssertionLifetime` 都会使 `Freeze()` panic。

## `jwks_uri` 的拉取

- 只请求 client 预登记的那一个地址：GET、无请求体、不带凭据、**不跟随重定向**、状态码必须是 200、响应体受上限约束。
- 缓存以 `jwks_uri` 为键。断言的 `kid` 在缓存中找不到时刷新一次（密钥轮换）；仍找不到则失败。
- 对同一地址的任何出站请求（首次、过期重拉、刷新）都受 `JwksMinRefreshInterval` 限制，并发请求合并为一次。拉取失败时本次认证按 `invalid_client` 失败；尚在缓存寿命内的旧密钥继续可用。
- **拨号约束的注入点**：wicket 不限制 `jwks_uri` 的目的地址（回环、链路本地、私网）。client 由宿主静态配置，目的地址由宿主负责；需要约束时通过 `Options.HTTPClient` 传入带自定义 `DialContext` 的 `Transport`。`HTTPClient` 的 `Timeout`、`CheckRedirect`、`Jar` 不被采用；`Transport` 为 nil 时使用 wicket 自建的带默认 TLS 校验的传输，不回落到 `http.DefaultTransport`。

## 失败响应

- **校验失败**（过期、`aud` / `iss` 不符、算法不被接受、验签失败、未知 `kid`、重放等）：各端点既有的 `invalid_client` 响应，不带任何区分失败原因的内容；同一端点上这些失败的状态码与响应体彼此相同。失败原因只进日志。
- **登记端口故障**（`Register` 返回重复之外的错误）：既不判为重放，也不放行。响应固定为状态码 500、`Cache-Control: no-store`、`Content-Type: text/plain; charset=utf-8`、响应体 `Internal Server Error`（带换行），不含协议错误码与底层错误文本，也不签发任何令牌。

## discovery

启用后，`token_endpoint_auth_methods_supported` 含 `private_key_jwt`，`token_endpoint_auth_signing_alg_values_supported` 为 `Options.SigningAlgorithms`。两者都出自已注册的断言 parser；未启用、或 `Discovery.ShowTokenEndpointAuthenticationMethods` 为假时都不出现。宿主以自定义条目写的 `token_endpoint_auth_signing_alg_values_supported` 一律被忽略并记一条 WARN。

## 日志

- 会记录：client id（或 API 资源名）、`alg`、截断后的 `kid`、失败类别（如 `expired`、`audience`、`signature`、`replay`、`key_not_found`、`registry_unavailable`）、`jwks_uri` 的 scheme 与 host。
- 不会记录：断言原文及其任何一段、签名、`jti`、登记键、`client_secret`、取回的 JWKS 内容、`Authorization` 头，以及登记适配器返回的错误文本（只记其 Go 类型名）。

## 自建端点的宿主须知

断言认证的包装发生在五个端点 handler 的装配工厂处；容器里 `validators.ClientSecretValidator` 与 `validators.ApiSecretValidator` 的单值解析结果仍是共享 secret 的校验器。wicket 今后新增的要求客户端认证的端点，须在其装配工厂里经同一个辅助函数（`di` 包内的 `clientAuthenticatorFromProvider` / `apiAuthenticatorFromProvider`）取得认证器，否则该端点不接受断言。宿主自己直接从容器解析上述两个接口来做客户端认证时，得到的校验器同样不接受断言。
