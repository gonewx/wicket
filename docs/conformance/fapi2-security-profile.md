# FAPI 2.0 Security Profile conformance 自测记录

> 状态：**自测记录，不是认证**。本文记录以 OpenID Foundation conformance suite 5.3.4 对开启高安全档位的 wicket 测试宿主运行 FAPI 2.0 Security Profile 授权服务器测试计划的一轮结果。各模块的状态与结果以 suite 导出为准，原样转录自 [`fapi2-security-profile-results.json`](./fapi2-security-profile-results.json)；本文不对任何模块作出强于该导出的结论。未通过、未完成、需人工截图评审以及因测试宿主所致的结果均逐条列出。

## 1. 被测对象

| 项 | 内容 |
| --- | --- |
| wicket 提交 | `239170e43bd27c8052e6c31e50664a5d3ebb5c59` |
| Go 版本 | `go1.27.0` |
| 测试宿主 | [`test/conformance/fapi2host`](../../test/conformance/fapi2host/main.go)（wicket 仓内的测试程序，不是部署模板） |

发布版本包含被测提交之后的提交，内容为：修正测试数据；修正两个导出常量的取值（`claims_locales_supported`、`claims_parameter_supported`），wicket 不把这两个键写入 discovery 文档；测试宿主改由常量拼出错误页匹配地址（取值不变）并拒绝以 `/\` 开头的返回地址；`Freeze` 对静态 client 列表增加签名算法检查（`TokenEndpointAuthSigningAlgorithms` 须落在档位收窄后的算法集内，测试宿主的 client 未设该字段，不受影响），并删除回环地址判定中一个不可达的分支（行为不变）。这些改动未经重新运行 suite；本轮各模块的请求都不经过它们改变的分支，本文据此认为记录的结果不受影响。

宿主配置要点：

- 开启高安全档位（`ServerConfig.EnableHighSecurityProfile()`），并启用其所需的 PAR（内存 store）、DPoP（默认选项）、`private_key_jwt` 与 `jti` 重放登记（内存实现）。
- 两个 client，均为 `private_key_jwt`（ES256）、要求 DPoP；第一个的回调为 `<suite>/test/a/<alias>/callback`，第二个的回调带查询串 `?dummy1=lorem&dummy2=ipsum`（suite 对第二个 client 如此发送）。
- 服务端签名密钥为启动时生成的 ES256 密钥，`kid` 取 RFC 7638 thumbprint，与 JWKS 中一致；client 密钥同样在每次启动时新生成。
- identity resource：`openid`、`profile`、`email`；测试用户 `alice`，带 `name` 与 `email` 两项 claim。
- 登录、同意与错误页由宿主提供：**不显示登录表单**，每个授权请求自动以测试用户登录并同意；错误页显示 wicket 返回的错误。
- HTTPS，启动时生成自签证书；TLS 最低 1.2，1.2 下只开 `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` 与 `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`（FAPI 2.0 Security Profile §5.2.2）。
- 所有数据均在内存中，进程退出即丢失。
- `-config <文件>` 把 suite 的测试配置写到该文件（权限 0600）。该文件**含两个 client 的私钥**，只应留在运行宿主的本机，不得提交。suite 的资源端点配置为 wicket 的 userinfo 端点（接受 DPoP 绑定的 access token）。

## 2. conformance suite

| 项 | 内容 |
| --- | --- |
| 版本 | 5.3.4（tag `release-v5.3.4`） |
| revision | `daca6ad2068468d42557ea1152f899cc3ac01a10` |
| 镜像 | `registry.gitlab.com/openid/conformance-suite@sha256:2a53917fd8df04a24f09203175295acc73a93fa156726973ad621297692113d6` |
| 运行时间 | 2026-11-15T19:25:03Z – 2026-11-15T19:42:18Z（UTC） |
| plan id | `GjHOsOujSwQL8` |

suite 在本地运行，各模块的日志 id 见下文结果表。suite 导出的原始压缩包含测试配置（其中有 client 私钥），因此不归档；仓内只保留剥离了密钥与令牌的逐模块结果。

## 3. 测试计划与变体

测试计划：`fapi2-security-profile-final-test-plan`（FAPI 2.0 Security Profile 授权服务器测试）。

| 变体 | 取值 | 选择理由 |
| --- | --- | --- |
| `openid` | `openid_connect` | wicket 是 OpenID Connect 提供方，授权码流程签发 ID token；该取值同时覆盖 OAuth 部分 |
| `client_auth_type` | `private_key_jwt` | 高安全档位只接受非对称客户端认证；宿主未配置客户端证书，故选 `private_key_jwt` |
| `sender_constrain` | `dpop` | 高安全档位要求发送方约束 token；宿主以 DPoP 实现 |
| `fapi_profile` | `plain_fapi` | 不附加任何地区生态的额外要求，只测 FAPI 2.0 Security Profile 本身 |
| `authorization_request_type` | `simple` | 不使用 Rich Authorization Requests（wicket 未实现 `authorization_details`） |
| `grant_management` | `disabled` | wicket 未实现 FAPI Grant Management |

模块级变体（由 suite 按计划确定）：`fapi_request_method=unsigned`、`fapi_response_mode=plain_response`。

## 4. 不适用或未运行的变体

| 变体取值 | 理由 |
| --- | --- |
| `client_auth_type=mtls`、`sender_constrain=mtls` | 测试宿主未配置客户端证书与 mTLS 端点；wicket 的 mTLS 客户端认证与证书绑定可另行配置宿主测试，本轮未运行 |
| `fapi_profile` 的生态子档位：`consumerdataright_au`、`openbanking_brazil`、`connectid_au`、`cbuae`、`openbanking_chile`、`ksa`、`fapi_client_credentials_grant` | 属地区生态或特定场景的附加要求，不在 FAPI 2.0 Security Profile 本身范围内 |
| `authorization_request_type=rar` | wicket 未实现 Rich Authorization Requests |
| `grant_management=enabled` | wicket 未实现 FAPI Grant Management |
| `openid=plain_oauth` | 与 `openid_connect` 共享同一服务端实现，本轮未单独运行 |

## 5. 逐模块结果

下表的"状态"与"结果"原样取自 suite 导出（`status` 与 `result` 字段）；"（无）"表示 suite 对该模块未给出结果。模块名省略共同前缀 `fapi2-security-profile-final-`。"截图评审项"列出 suite 日志中要求上传截图、由人工评审的条件（REVIEW）；本文不把这些条件视为已评审。

| # | 模块 | suite 日志 id | 状态 | 结果 | 失败条件 | 警告条件 | 截图评审项 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `discovery-end-point-verification` | `cVOvLPD1XLk2u1t` | FINISHED | PASSED | — | — | — |
| 2 | `happy-flow` | `o61EgTPlmWwpZ9H` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 3 | `user-rejects-authentication` | `lzm7uoDgRMm7fN9` | FINISHED | FAILED | `EnsureErrorFromAuthorizationEndpointResponse`<br>`ExpectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest` | `CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint` | — |
| 4 | `ensure-authorization-request-without-state-success` | `DNmwwR6Ib0fBfEQ` | FINISHED | PASSED | — | — | — |
| 5 | `ensure-authorization-request-without-nonce-success` | `6Y7demIOa6p5Nqj` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 6 | `ensure-authorization-request-with-64-char-nonce-success` | `GlYnFnwIOfUWsn9` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 7 | `ensure-other-scope-order-succeeds` | `ZFaYYDem8ynwVt2` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 8 | `test-claims-parameter-identity-claims` | `eFbFvVxn1lObmKL` | FINISHED | SKIPPED | — | — | — |
| 9 | `access-token-type-header-case-sensitivity` | `yKFnnEl9YHzQCRv` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 10 | `check-dpop-proof-nbf-exp` | `35VSJkz548I2eQ7` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 11 | `ensure-dpopproof-with-iat-10seconds-before-succeeds` | `mr9k6f5Ni5deEU1` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 12 | `ensure-dpopproof-with-iat-10seconds-after-succeeds` | `XszRkHD3hoBXNP3` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 13 | `ensure-mismatched-dpop-jkt-fails` | `I2mYaxWr209vwIa` | FINISHED | FAILED | `EnsurePARInvalidRequestOrInvalidDpopProof` | — | — |
| 14 | `ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt` | `kd5qWKXqsYiYGma` | FINISHED | FAILED | `CheckTokenEndpointReturnedInvalidRequestGrantOrDPopProofError` | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 15 | `ensure-token-endpoint-fails-with-mismatched-dpop-jkt` | `I2nqvzxG61oAoFl` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 16 | `ensure-dpopproof-at-par-endpoint-binding-success` | `MvR6K1EUvdeLsgv` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 17 | `ensure-dpop-auth-code-binding-success` | `DGMujzSQa9UGTXE` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 18 | `ensure-different-nonce-inside-and-outside-request-object` | `xk7PTUJtFN5Qdup` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | `ExpectRequestDifferentNonceInsideAndOutsideErrorPage` |
| 19 | `ensure-different-state-inside-and-outside-request-object` | `DOFOXuRowbxlOql` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | `ExpectRequestDifferentStateInsideAndOutsideErrorPage` |
| 20 | `ensure-authorization-request-with-long-nonce` | `JQ5gOTziiK10F4A` | FINISHED | PASSED | — | — | — |
| 21 | `ensure-authorization-request-with-long-state` | `gtU6ZFu5entn2pp` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | `ExpectRequestObjectWithLongStateErrorPage` |
| 22 | `state-only-outside-request-object-not-used` | `U4Vpy8JdSrquGMG` | FINISHED | PASSED | — | — | `ExpectRequestObjectMissingStateErrorPage` |
| 23 | `ensure-request-object-without-redirect-uri-fails` | `woNpe8TqN0Xp2rc` | FINISHED | PASSED | — | — | — |
| 24 | `plain-fapi-tolerate-unregistered-redirect-uri` | `9d9EEM9dkyZcAtN` | FINISHED | PASSED | — | — | — |
| 25 | `ensure-unsigned-authorization-request-without-using-par-fails` | `wA3TkKg9tqpE1FJ` | INTERRUPTED | （无） | — | — | `ExpectAuthorizationRequestWithoutRequestObjectErrorPage` |
| 26 | `ensure-redirect-uri-in-authorization-request` | `4On9koFOhqSbxs6` | FINISHED | PASSED | — | — | — |
| 27 | `ensure-response-type-code-idtoken-fails` | `XHhh9F53GdGC1nK` | FINISHED | PASSED | — | — | — |
| 28 | `ensure-response-type-token-fails` | `70y1GVgFQkrOVmO` | FINISHED | PASSED | — | — | — |
| 29 | `ensure-client-id-in-token-endpoint` | `E9aaJeNrhapFz5a` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 30 | `ensure-holder-of-key-required` | `EEKUuaam3PanYmF` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 31 | `ensure-holder-of-key-required-at-non-alias-token-endpoint` | `DRQIwyh1JYHnttx` | FINISHED | SKIPPED | — | — | — |
| 32 | `ensure-authorization-code-is-bound-to-client` | `IfrnVcBfzTwZFFw` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 33 | `attempt-reuse-authorization-code-after-one-second` | `e5C8jQqWVJTnLHN` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint`<br>`EnsureHttpStatusCodeIs4xx` | — |
| 34 | `ensure-token-endpoint-fails-with-expired-auth-code` | `E9o26QXagh1paIJ` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 35 | `ensure-signed-client-assertion-with-RS256-fails` | `ONefk6zIJZz7y9p` | FINISHED | SKIPPED | — | — | — |
| 36 | `ensure-client-assertion-in-token-endpoint` | `fY9ZfGlRBeklltg` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 37 | `ensure-client-assertion-with-exp-is-5-minutes-in-past-fails` | `wto9BnnVJR4t9NY` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 38 | `ensure-client-assertion-with-wrong-aud-fails` | `cGdc59GpxvRicZ5` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 39 | `ensure-client-assertion-with-no-sub-fails` | `wCpmmEaZsOzsO83` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 40 | `ensure-invalid-client-assertions-fail` | `kbthjB1l50iOi8V` | FINISHED | PASSED | — | — | — |
| 41 | `dpop-negative-tests` | `ROG5I8QE42WwncY` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 42 | `refresh-token` | `4l5B7lJQyyKPNwh` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 43 | `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `mR8oKP7NVT8xJov` | INTERRUPTED | FAILED | `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | — | — |
| 44 | `par-attempt-reuse-request_uri` | `13HPrubRd6WfxDc` | INTERRUPTED | UNKNOWN | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | `ExpectInvalidRequestUriErrorPage` |
| 45 | `par-attempt-to-use-expired-request_uri` | `Era73C4S3wIHL4M` | INTERRUPTED | （无） | — | — | `ExpectInvalidRequestUriErrorPage` |
| 46 | `par-attempt-to-use-request_uri-for-different-client` | `zeJMiujTMQh9gVl` | INTERRUPTED | （无） | — | — | `ExpectInvalidRequestUriErrorPage` |
| 47 | `par-authorization-request-containing-request_uri-form-param` | `CX8L1gw2GMpw0n2` | FINISHED | PASSED | — | — | — |
| 48 | `par-attempt-invalid-http-method` | `IpVmlFMvrMJ6e8d` | FINISHED | PASSED | — | — | — |
| 49 | `par-ensure-pkce-required` | `ho9gO7Brxz1zL8G` | FINISHED | PASSED | — | — | — |
| 50 | `ensure-pkce-code-verifier-required` | `3LuAh1Xf0qHid4O` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 51 | `incorrect-pkce-code-verifier-rejected` | `bQMLJo3g3Jdf5jN` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |
| 52 | `par-plain-pkce-rejected` | `LbbokHudYpgi9K1` | FINISHED | PASSED | — | — | — |
| 53 | `par-without-duplicate-parameters` | `DQ53tIXrryoryDd` | FINISHED | WARNING | — | `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | — |

### 汇总

共 53 个模块。

| 状态 | 结果 | 模块数 |
| --- | --- | --- |
| FINISHED | PASSED | 14 |
| FINISHED | WARNING | 28 |
| FINISHED | FAILED | 3 |
| FINISHED | SKIPPED | 3 |
| INTERRUPTED | FAILED | 1 |
| INTERRUPTED | UNKNOWN | 1 |
| INTERRUPTED | （无） | 3 |
| **合计** | | **53** |

按状态：FINISHED 48、INTERRUPTED 5。按结果：PASSED 14、WARNING 28、FAILED 4（其中 1 个处于 INTERRUPTED）、SKIPPED 3、UNKNOWN 1、无结果 3。

28 个 WARNING 中，27 个只有一项警告 `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint`（授权响应带 `scope` 参数）；`attempt-reuse-authorization-code-after-one-second` 另有一项 `EnsureHttpStatusCodeIs4xx`。

## 6. 未通过与未完成项

归因分三类：**wicket 缺口**（wicket 的行为与 suite 预期不符）、**宿主限制**（测试宿主无法按 suite 预期完成交互）、**需人工截图评审**（suite 等待上传截图）。

### 6.1 FAILED

| 模块 | 状态 / 结果 | 归因 | 说明与去向 |
| --- | --- | --- | --- |
| `user-rejects-authentication` | FINISHED / FAILED | 宿主限制 | 该模块要求用户在登录页拒绝授权，期望授权端点返回 `access_denied`。宿主不显示登录表单、自动登录并同意，无法拒绝，授权端点未返回错误。需以能显示登录与拒绝的宿主复测，本轮未完成。 |
| `ensure-mismatched-dpop-jkt-fails` | FINISHED / FAILED | wicket 缺口 | 期望 PAR 端点在请求的 `DPoP` 头与 `dpop_jkt` 不一致时以 `invalid_request` 或 `invalid_dpop_proof` 拒绝。wicket 的 PAR 端点不读取 `DPoP` 头（RFC 9449 §10.1 允许 PAR 请求携带 DPoP proof，并要求其与 `dpop_jkt` 同时出现时一致）。列为后续改进，尚未排期。 |
| `ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt` | FINISHED / FAILED | wicket 缺口 | 同一原因：PAR 请求所带 proof 的密钥未用于绑定授权码，token 请求换用另一把 DPoP 密钥时 token 端点仍签发。去向同上。 |
| `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | INTERRUPTED / FAILED | 宿主限制 | 该模块要求首次访问授权端点时停在登录页、不完成登录，再以同一 `request_uri` 重新发起。宿主自动登录，首次访问即完成授权，模块被中断。需以能显示登录页的宿主复测，本轮未完成。 |

第 5 节结果表中，`par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` 的"失败条件"一栏是模块自身的名称：对这个被中断的模块，suite 把失败记在模块名下。suite 记录的中断原因原文为：“The user was authenticated on the initial visit to login page. This must not be attempted until the second visit. If no login was attempted then please delete related cookies or logout from the server before re-running.”

### 6.2 INTERRUPTED（等待截图评审超时）

以下 4 个模块期望 wicket 拒绝请求并显示错误页，suite 要求上传错误页截图由人工评审。运行脚本时无人上传截图，模块在等待中超时中断。它们的结果**未评审、不计为通过**；需在 suite 界面补传截图后由评审者判定。

| 模块 | 状态 / 结果 | 截图评审项 |
| --- | --- | --- |
| `ensure-unsigned-authorization-request-without-using-par-fails` | INTERRUPTED / （无） | `ExpectAuthorizationRequestWithoutRequestObjectErrorPage` |
| `par-attempt-reuse-request_uri` | INTERRUPTED / UNKNOWN | `ExpectInvalidRequestUriErrorPage`（另有警告 `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint`） |
| `par-attempt-to-use-expired-request_uri` | INTERRUPTED / （无） | `ExpectInvalidRequestUriErrorPage` |
| `par-attempt-to-use-request_uri-for-different-client` | INTERRUPTED / （无） | `ExpectInvalidRequestUriErrorPage` |

### 6.3 已完成但日志含截图评审项

以下 4 个模块状态为 FINISHED，suite 导出的结果如表；其日志中含要求上传错误页截图的条件，本轮未上传截图。表中结果即 suite 的导出，本文不把其中的截图项视为已评审。

| 模块 | 状态 / 结果 | 截图评审项 |
| --- | --- | --- |
| `ensure-different-nonce-inside-and-outside-request-object` | FINISHED / WARNING | `ExpectRequestDifferentNonceInsideAndOutsideErrorPage` |
| `ensure-different-state-inside-and-outside-request-object` | FINISHED / WARNING | `ExpectRequestDifferentStateInsideAndOutsideErrorPage` |
| `ensure-authorization-request-with-long-state` | FINISHED / WARNING | `ExpectRequestObjectWithLongStateErrorPage` |
| `state-only-outside-request-object-not-used` | FINISHED / PASSED | `ExpectRequestObjectMissingStateErrorPage` |

### 6.4 SKIPPED

跳过理由原样引自 suite：

| 模块 | 理由 |
| --- | --- |
| `test-claims-parameter-identity-claims` | The 'claims_parameter_supported' server metadata indicates that it does not support the claims parameter (which is permitted behaviour), so claims behaviour cannot be tested. |
| `ensure-holder-of-key-required-at-non-alias-token-endpoint` | The server does not publish a token endpoint in mtls_endpoint_aliases that differs from token_endpoint, so there is no separate token endpoint to test. |
| `ensure-signed-client-assertion-with-RS256-fails` | This test requires RSA keys to be performed, the alg in client configuration is 'ES256' so this test is being skipped. If your server does not support PS256 then this will not prevent you certifying. |

前两项分别因 wicket 未宣告支持 `claims` 请求参数、未配置 mTLS 端点别名；第三项因宿主的 client 使用 ES256 密钥。

### 6.5 WARNING

| 警告 | 涉及模块 | 归因 | 说明与去向 |
| --- | --- | --- | --- |
| `ValidateSuccessfulAuthCodeFlowResponseFromAuthorizationEndpoint` | 28 个 WARNING 模块全部，另见于 `ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt` 与 `par-attempt-reuse-request_uri` | wicket 行为 | 授权成功响应带 `scope` 参数，该参数不在 OAuth 2.0 授权码响应与 FAPI 2.0 的定义之内。是否去掉属行为变更，待定。 |
| `EnsureHttpStatusCodeIs4xx` | `attempt-reuse-authorization-code-after-one-second` | wicket 缺口 | 授权码被第二次兑换时 wicket 拒绝，但第一次兑换签发的 access token 仍可访问 userinfo（返回 200）。RFC 6749 §4.1.2 规定此时**应当**（SHOULD）撤销已签发的 token；JWT access token 自包含，撤销需新机制。列为后续改进，尚未排期。 |
| `CheckForUnexpectedParametersInErrorResponseFromAuthorizationEndpoint` | `user-rejects-authentication` | 宿主限制 | 出现在因宿主自动登录而失败的模块中，见 6.1。 |

## 7. 自测中发现并已修复的缺陷

以下缺陷在自测中发现，已在被测提交中修复，各带回归测试（被测提交之后的提交见第 1 节的说明）：

1. **token 端点错误响应不是 JSON。** 此前错误响应在写出状态码之后才设置响应头，`Content-Type` 与 `Cache-Control` 未被发送，客户端收到的是 `text/plain`；`Custom` 中的附加条目被嵌套在 `custom` 键下，描述为空时仍发送空的 `error_description`。现在错误响应以 `Content-Type: application/json` 与 `Cache-Control: no-store` 发送（RFC 6749 §5.2），附加条目与 `error` 并列（不覆盖 `error`），空描述省略。
2. **discovery 未宣告 `claims_supported`。** discovery 文档把支持的 claim 列表放在拼写错误的键 `claims._supported` 下，现在改为 `claims_supported`。
3. **refresh token 可被其他 client 兑换。** 此前 token 端点不比较 refresh token 所属的 client 与发起请求的已认证 client，任一 client 都能兑换他人的 refresh token 并获得签发给对方的 token。现在他人的 refresh token 按不存在处理，返回 `invalid_grant`，其所属 client 仍可正常兑换。

## 8. 复现步骤

1. **启动 suite。** 取 conformance suite 仓库（本轮为 revision `daca6ad2068468d42557ea1152f899cc3ac01a10`），以其 `docker-compose-prebuilt.yml` 启动预构建镜像（见第 2 节）。suite 容器需能以 `host.docker.internal` 访问运行宿主的本机；Linux 上加一个覆盖文件把该名映射到 `host-gateway`：

   ```yaml
   # override.yml
   services:
     server:
       extra_hosts:
         - "host.docker.internal:host-gateway"
   ```

   ```bash
   docker compose -f docker-compose-prebuilt.yml -f override.yml up -d
   ```

   suite 界面与 API 在本机 `https://localhost:8443`（自签证书）。
2. **启动测试宿主并写出 suite 配置。** 在 wicket 仓库根目录：

   ```bash
   GOWORK=off mise exec -- go run ./test/conformance/fapi2host -config /path/outside/repo/fapi2-suite-config.json
   ```

   默认值：`-addr :9443`、`-issuer https://host.docker.internal:9443`、`-suite https://localhost.emobix.co.uk:8443`（suite 容器内的对外地址，决定 client 的回调）、`-alias wicket-fapi2`。服务端与 client 密钥在每次启动时重新生成，配置文件只对写出它的那个进程有效；宿主重启后需重新写出配置。配置文件含 client 私钥，不要放进仓库。
3. **运行测试计划。** 先按 suite 的 `scripts/requirements.txt` 装好依赖（`httpx`、`pyparsing`），在 suite 仓库的 `scripts/` 目录下：

   ```bash
   CONFORMANCE_SERVER=https://localhost:8443/ CONFORMANCE_SERVER_MTLS=https://localhost:8444/ \
   CONFORMANCE_DEV_MODE=1 CONFORMANCE_MAX_CONSECUTIVE_FAILURES=1000 \
     python3 run-test-plan.py --no-parallel --export-dir /path/outside/repo/export \
     'fapi2-security-profile-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][authorization_request_type=simple][grant_management=disabled]' \
     /path/outside/repo/fapi2-suite-config.json
   ```

   `CONFORMANCE_MAX_CONSECUTIVE_FAILURES` 调高是为了不让脚本在连续几个模块未完成时提前终止整轮。要求截图评审的模块会停在等待上传截图的状态，脚本对每个模块最多等 240 秒，超时后模块被中断（见 6.2）。如需完成这些模块，在 suite 界面打开对应日志上传错误页截图。
4. **导出结果。** 在 suite 界面导出该 plan 的结果。导出的压缩包含测试配置与私钥，不要归档原件；只保留各模块的名称、日志 id、状态、结果与条件名。
