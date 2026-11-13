# Wicket

OpenID Connect / OAuth 2.0 身份认证服务器库（Go 中间件）。

Wicket 作为中间件嵌入宿主 HTTP 应用，提供 OIDC/OAuth 2.0 协议端点（授权、令牌、发现、用户信息、内省、令牌撤销、会话管理、CIBA），并支持多种外部身份提供者（Google、Facebook、Apple）与 JWT Bearer 认证。

## 特性

- OIDC 授权码流（含 PKCE）、Discovery、UserInfo、Introspection
- 令牌端点：`authorization_code`、`refresh_token`、`client_credentials`、CIBA、设备码（`urn:ietf:params:oauth:grant-type:device_code`）
- 令牌撤销（RFC 7009）：`POST /connect/revocation`，客户端认证与令牌端点相同（含只凭 `client_id` 的公共客户端），可撤销 refresh token（连带同一用户、同一客户端的 reference access token）与 reference access token；discovery 宣告 `revocation_endpoint`，`EnableTokenRevocationEndpoint=false` 时端点返回 404 且不宣告。注意：令牌端点目前只签发 JWT access token，没有生产路径写入 reference token store，只有宿主自行写入的令牌才是 reference token；提交 JWT 形态的令牌（字符串含 `.`）返回 400 `unsupported_token_type`，不撤销，令牌在过期前仍然有效。认证失败返回 `invalid_client`（带 `Authorization` 头时 401 并附 `WWW-Authenticate`，否则 400）；不含 `.` 的未知、已撤销或属于其他客户端的令牌返回 200（他人令牌静默不撤销）；不支持的 `token_type_hint` 返回 400 `unsupported_token_type`；详见 [docs/api-contracts.md](docs/api-contracts.md)
- 设备授权流（RFC 8628）：`POST /connect/deviceauthorization`，客户端认证方式与令牌端点相同，公共客户端只需 `client_id`；设备在令牌端点以 device_code 授权类型轮询，按 RFC 8628 返回 `authorization_pending`、`slow_down`、`access_denied`、`expired_token`，同一 device_code 只能兑换一次（并发轮询除外，见已知限制）。wicket 不带验证页面：宿主的验证页面经 `services.DeviceFlowInteractionService` 按 user code 取授权上下文，再批准（可收窄 scope，传入的已认证主体至少要有 `sub`）或拒绝。不提供"记住同意"，每次都须用户明确批准；user code 的尝试限速由宿主验证页面负责。discovery 宣告 `device_authorization_endpoint`，`EnableDeviceAuthorizationEndpoint=false` 时端点返回 404 且不宣告。轮询间隔默认 5 秒（`DeviceFlow.Interval`），客户端可用 `PollingInterval` 覆盖节流间隔。其他已知限制见 [API 端点](docs/api-contracts.md)
- Back-Channel Logout 发送（OIDC Back-Channel Logout 1.0）：开启 server-side sessions（`ServerSideSessions.Enabled`）且 check-session 端点开启时提供，discovery 宣告 `backchannel_logout_supported` / `backchannel_logout_session_supported`；默认装配不开启 server-side sessions，因此不宣告、不发送。宿主登录时须经 `services.UserSession.CreateSessionId` 建立会话。用户经 `/connect/endsession` 登出、浏览器加载宿主登出页渲染的回调 iframe 时，wicket 为该会话中登记了 `BackChannelLogoutUri` 的客户端签发 `typ=logout+jwt` 的 logout token（两分钟有效，带 `sid` 与 `sub`，不带 `nonce`），以表单 POST 并发投递，最多等待 5 秒；单个 RP 失败只记日志，不影响登出。缺省 HTTP client 5 秒超时且不跟随重定向；宿主自行注入的 client 必须设置超时，其重定向策略由宿主负责。开启 server-side sessions 时 ID Token 带 `sid`。已知限制见 [API 端点](docs/api-contracts.md)
- 端点开关：授权（含授权回调）、令牌、内省、CIBA 端点各有 `Endpoints.Enable*` 开关（`EnableAuthorizeEndpoint`、`EnableTokenEndpoint`、`EnableIntrospectionEndpoint`、`EnableBackchannelAuthenticationEndpoint`），关闭后端点对任何请求返回 404 且 discovery 不宣告，默认均开启；开关不联动，直接构造 handler 时的情形与已知限制详见 [docs/api-contracts.md](docs/api-contracts.md)
- Discovery 按当前装配实际可服务的能力输出宣告（已注册路由、能力实现与客户端认证解析器），未落地的能力不会出现在文档中
- 外部 IdP：Google / Facebook / Apple / JWT Bearer + 运行时动态方案
- 无状态令牌验证三件套：`oidcverify`（本地验签）、`wechatverify`（微信服务端交换）、`phoneverify`（阿里号码认证）
- 存储端口三族（storage / session / keymgmt）+ 契约测试套件（`storagetest` / `sessiontest` / `keymgmttest`）
- 官方 PostgreSQL 适配器：[github.com/gonewx/wicket-pg](https://github.com/gonewx/wicket-pg)

## 快速开始

```go
root := di.NewRoot()
defer root.Close()

cfg := godi.GetRequired[*di.ServerConfig](root)
cfg.SetClients(...)
cfg.SetSigningCredentialStores(...)

srv := server.NewServer(root)
mux := http.NewServeMux()
mux.Handle("/", srv.UseWicket()(yourAppHandler))
http.ListenAndServe(":8080", mux)
```

## 文档

- [文档索引](docs/index.md)
- [架构](docs/architecture.md)
- [API 端点](docs/api-contracts.md)
- [开发指南](docs/development-guide.md)
- [存储持久化接入指南](docs/storage-persistence-guide.md)
- [外部认证提供者配置指南](docs/external-providers-guide.md)

## 要求

- Go 1.27 工具链（mise pin `1.27.0`）

## 许可证

Apache 2.0，详见 [LICENSE](LICENSE) 与 [PROVENANCE.md](PROVENANCE.md)。
