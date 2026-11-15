# mTLS 客户端认证接入指南（RFC 8705）

> 状态：**已落地，默认关闭**。本特性让机密 client 用 TLS 客户端证书完成客户端认证，支持 RFC 8705 的两种方式：PKI 方式 `tls_client_auth` 与自签方式 `self_signed_tls_client_auth`。未启用时，wicket 的路由、认证、discovery 文档与既有 client 的行为都与此前相同。

## 概述

| 项 | 内容 |
| --- | --- |
| 启用入口 | `ServerConfig.EnableClientCertificateAuthentication(clientcert.Options)`，须在 `Freeze()` 之前调用 |
| 证书来源缝 | `ServerConfig.SetClientCertificateSource(clientcert.CertificateSource)`，未注入（或注入 nil）时取直连 TLS 对端证书 |
| 覆盖端点 | token、revocation、backchannel authentication（CIBA）、device authorization |
| 端点别名 | `/connect/mtls/token`、`/connect/mtls/revocation`、`/connect/mtls/introspect`、`/connect/mtls/deviceauthorization`，与主端点由同一 handler 服务 |
| client 识别 | 请求体（`application/x-www-form-urlencoded`）必须带 `client_id`（RFC 8705 §2） |
| 失败响应 | 各端点既有的 `invalid_client` 响应，不带描述；日志只记 `client_id`，不记证书内容 |

## 启用步骤

根容器在 `di.NewRoot()` 内就构造好全部单例，因此启用声明发生在根容器建好之后、`Freeze()` 之前：

```go
root, err := di.NewRoot()
// ...
roots := x509.NewCertPool()
roots.AppendCertsFromPEM(clientCaPem)

cfg := root.ServerConfig()
cfg.EnableClientCertificateAuthentication(clientcert.Options{
	// 为 nil 时 tls_client_auth 不可用，只剩 self_signed_tls_client_auth。
	TrustedAuthorities: roots,
})
// 可选：反向代理场景见下文。
// cfg.SetClientCertificateSource(myProxySource{})
cfg.Freeze()
```

### 启用声明与 `MutualTls.Enabled` 的分工

- `EnableClientCertificateAuthentication` 决定**实现是否存在**：两种方法的 parser、认证器、四个别名路由。
- 既有的 `WicketOptions.MutualTls.Enabled` 仍只决定**是否在 discovery 中宣告**。
- 宣告需要二者同时成立：此时 `token_endpoint_auth_methods_supported` 列出可用的 tls 方法（无重复），`mtls_endpoint_aliases` 列出别名。
- 只开启用声明、不开 `MutualTls.Enabled`：认证照常可用，但 discovery 不宣告任何 mTLS 内容。
- 只开 `MutualTls.Enabled`、不开启用声明：维持此前行为，宣告守卫撤下 mTLS 条目并记 Warn。
- 只启用了自签方式（未配置 `TrustedAuthorities`）而开 `MutualTls.Enabled` 时，`tls_client_auth` 被宣告守卫撤下并照例记 Warn。
- `MutualTls.DomainName` 决定别名形态：为空时为路径形态（`<base>/connect/mtls/token`），含点时为独立域名（`https://<domain>/connect/token`），不含点时为子域（`https://<name>.<base host>/connect/token`）。域名形态下别名主机由宿主自行部署并转发到同一服务。
- `tls_client_certificate_bound_access_tokens` 同样需要二者同时成立才宣告（值为 `true`），见下文“证书绑定 access token”。

## 证书来源缝

`clientcert.CertificateSource` 只有一个方法：

```go
ClientCertificates(request *http.Request) []*x509.Certificate // 叶子在前，无证书返回 nil
```

- 默认实现 `clientcert.ConnectionCertificateSource` 读取 `request.TLS.PeerCertificates`。
- **wicket 不内置对任何代理头的信任。** 部署在终止 TLS 的反向代理之后时，宿主自行实现来源（例如从代理转发的头中解析证书），并自行保证只有可信代理能设置该头；这一信任决定由宿主负责。

## TLS 层配置

直连部署时，服务器的 `tls.Config` 必须请求客户端证书，否则请求中不会有对端证书：

```go
server.TLSConfig = &tls.Config{
	// 自签证书无法通过 TLS 层的链校验，因此不能用 RequireAndVerifyClientCert；
	// 用 RequestClientCert 或 RequireAnyClientCert，链校验由 wicket 完成。
	ClientAuth: tls.RequestClientCert,
}
```

只用 PKI 方式时也可以在 TLS 层使用 `VerifyClientCertIfGiven` 等设置，但 wicket 仍会按 `TrustedAuthorities` 再校验一次。

## client 登记

`models.Client` 内嵌的 `ClientAuthenticationMetadata` 新增 RFC 8705 §2.1.2 的元数据字段：

| `TokenEndpointAuthMethod` | 需要的字段 |
| --- | --- |
| `tls_client_auth` | `TlsClientAuthSubjectDn`、`TlsClientAuthSanDns`、`TlsClientAuthSanUri`、`TlsClientAuthSanIp`、`TlsClientAuthSanEmail` 中**恰好一个**非空 |
| `self_signed_tls_client_auth` | 内联 `Jwks`，某个 key 的 `x5c[0]` 是该 client 的证书 |

配置校验 fail-closed：方法未启用（未调用启用声明，或 `tls_client_auth` 缺 `TrustedAuthorities`）、PKI client 未登记或登记了多个 subject 字段、自签 client 无 `Jwks` 时，client 被判为无效配置，等同不存在。

## 匹配规则

**PKI 方式（`tls_client_auth`）**

1. 链校验：以出示的叶子证书为终端，其余出示证书作中间证书，`TrustedAuthorities` 为根，时间取 wicket 时钟，`KeyUsages` 为 `ExtKeyUsageClientAuth`。这是 wicket 的收紧（RFC 8705 未要求）：Go 对不带扩展密钥用途的证书放行，只拒绝带其他扩展密钥用途（例如仅 `serverAuth`）的证书。
2. 按登记的唯一字段匹配叶子证书：
   - `TlsClientAuthSubjectDn`：与 `leaf.Subject.String()`（Go 的 RFC 4514 渲染）**逐字相等**，不做 RDN 语义比较，属性顺序、空格、转义都必须一致；
   - `TlsClientAuthSanDns`：与任一 dNSName 不分大小写相等，不展开通配符；
   - `TlsClientAuthSanUri`：与任一 URI 的字符串形式相等；
   - `TlsClientAuthSanIp`：解析后与任一 iPAddress 相等（IPv6 的不同写法视为相同）；
   - `TlsClientAuthSanEmail`：与任一 rfc822Name 相等。

**自签方式（`self_signed_tls_client_auth`）**

叶子证书的 DER 与登记 `Jwks` 中任一 key 的 `x5c[0]`（标准 base64）逐字节相等即通过。不做链校验，也不检查有效期：RFC 8705 §2.2 中信任来自登记本身。轮换证书就是更新登记的 `Jwks`。

**通用规则**

- 登记 tls 方法的 client 只能用证书认证：同时带 `client_secret`、Basic 头、`client_assertion` 或 `client_assertion_type` 一律失败；不带证书失败；不带 `client_id`、经其他方式认证成功也会被改判失败。
- 未登记 tls 方法的 client 不受影响，无论是否出示证书，都交由原有认证链处理。
- 认证成功的结果携带 `Type = X509Certificate` 的 `ParsedSecret`，不携带证书本身。

## 证书绑定 access token（RFC 8705 §3）

启用声明 `EnableClientCertificateAuthentication` 同时让证书绑定 access token 可用，不另设开关。

### client 登记

在 `ClientAuthenticationMetadata` 上置 `TlsClientCertificateBoundAccessTokens = true`（RFC 8705 §3.4 元数据名）。该 client 可以用证书认证，也可以用 `client_secret` 等其他方式认证；无论哪种方式，token 请求都必须出示客户端证书。

配置校验 fail-closed，以下登记判为无效配置（等同不存在）：

- 未调用启用声明；
- 公共 client（`RequireClientSecret = false`）：其 refresh token 不绑定，被窃后可换得绑定到窃取者证书的 token；
- 同时 `AllowAccessTokensViaBrowser = true`：前端信道签发的 token 无法绑定。

### 签发规则

- token 端点（含 `/connect/mtls/token` 别名）为该 client 签发的每个 access token 都绑定到本次请求出示的叶子证书：JWT 带 `"cnf":{"x5t#S256":"<指纹>"}`，指纹是证书 DER 编码的 SHA-256 摘要的 base64url（无填充）编码。
- 不出示证书的 token 请求在客户端认证阶段就以 `invalid_client`（无描述）拒绝，早于授权码取出、refresh token 轮换与 device code 兑换，因此授权码与 refresh token 不会因此被消耗。
- refresh：新 access token 绑定到**本次 refresh 请求**出示的证书，与 `UpdateAccessTokenClaimsOnRefresh` 的取值无关。refresh token 本身不绑定。
- reference access token（`AccessTokenType = Reference`）的存储记录同时保存 `Token.Confirmation` 与一条 `cnf` claim，校验侧因此对 JWT 与 reference 一视同仁。
- 未登记该标志的 client 签发结果与此前一致。

### 资源端校验

- **userinfo**：携带 `cnf.x5t#S256` 的 token 必须随同一证书出示，否则 401 `invalid_token`，不说明原因；`cnf` 不是对象、`x5t#S256` 不是非空字符串、或出现多个 `cnf` 一律按不一致拒绝。不带 `cnf` 的 token 行为不变。userinfo 响应本身不含 `cnf`。证书来源与 token 端点相同（`SetClientCertificateSource` 注入的来源或 TLS 连接）。`cnf` 同时含 DPoP 的 `jkt` 时，token 还必须以 `DPoP` 方案带匹配的 proof 出示，两项绑定都满足才通过；以 Bearer 出示一律拒绝（见 [API 契约 · userinfo 与 introspection](./api-contracts.md#userinfo-与-introspection)）。
- **userinfo 不在 `mtls_endpoint_aliases` 中**：无论别名是路径形态、独立域名还是子域形态，client 都在主机的 userinfo 路由上访问 userinfo，宿主须在主 userinfo 路由上请求客户端证书（例如 `tls.RequestClientCert`），否则绑定 token 无法通过校验。
- **introspection**：active 响应对绑定的 JWT 与 reference token 都返回 `cnf`。
- **JWT Bearer handler（`auth/jwt`）**：设置 `Options.CertificateBindingSource`（形状同 `clientcert.CertificateSource`）后，绑定 token 证书不符或缺失时认证失败（`jwt.ErrCertificateBindingMismatch`），未绑定 token 照常通过；字段为 nil 时与此前一致。同时设置 `Options.DPoP` 时，`cnf` 兼含 `x5t#S256` 与 `jkt` 的 token 须两项绑定都满足：证书不符先失败（`invalid_token`），且不消耗 proof 的 `jti`（见 [外部提供者指南 · JWT Bearer 的 DPoP 校验](./external-providers-guide.md#dpop-校验rfc-9449)）。

```go
opts.CertificateBindingSource = clientcert.ConnectionCertificateSource{}
```

### discovery 宣告

`tls_client_certificate_bound_access_tokens: true` 仅在启用声明与 `MutualTls.Enabled` 同时成立时宣告；任一不成立都不宣告。

## 未支持项

- refresh token 本身不绑定（RFC 8705 §4 的公共 client refresh token 绑定未实现）；公共 client 与前端信道 token 的 client 不可登记 `TlsClientCertificateBoundAccessTokens`。
- 不支持 DPoP（`jkt`）。
- API 资源（introspection 的调用方）不支持 mTLS 认证；`/connect/mtls/introspect` 别名照常服务，但调用方按原有方式认证。
- `self_signed_tls_client_auth` 只支持内联 `Jwks`，不支持 `jwks_uri`。
- 不内置任何代理头信任，见“证书来源缝”。
