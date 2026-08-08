# Wicket 架构文档

## 概述

Wicket 采用分层服务架构，以 godi 依赖注入组合根为核心装配机制。整体设计遵循依赖倒置原则：接口定义在消费侧，实现通过组合根注入。

## 架构模式

```
┌─────────────────────────────────────────────────────────┐
│                    宿主 HTTP 应用                         │
│  server.UseWicket() → 中间件链                           │
├─────────────────────────────────────────────────────────┤
│  hosting.Middleware → EndpointRouter → Handler 分发       │
├─────────────────────────────────────────────────────────┤
│  handlers/          协议端点处理器（Transient）            │
│  ├── AuthorizeHandler                                   │
│  ├── TokenHandler                                       │
│  ├── DiscoveryHandler / DiscoveryKeyHandler             │
│  ├── UserInfoHandler                                    │
│  ├── IntrospectionHandler                               │
│  ├── EndSessionHandler / EndSessionCallbackHandler      │
│  ├── CheckSessionHandler                                │
│  └── BackchannelAuthenticationHandler                   │
├─────────────────────────────────────────────────────────┤
│  validators/        请求验证层                            │
│  responses/         响应生成层                            │
│  services/          业务服务层                            │
├─────────────────────────────────────────────────────────┤
│  storage/           存储抽象层（端口接口 + 内存实现）        │
│  session/           服务端会话存储（端口 + 内存实现）       │
│  keymgmt/           密钥管理（端口 + 内存实现）            │
├─────────────────────────────────────────────────────────┤
│  di/                组合根（godi 装配 + 代码生成）         │
│  config/            配置选项体系                          │
└─────────────────────────────────────────────────────────┘
```

## 核心组件

### 组合根（di/）

- `di/root.go` — `//go:generate godi-gen` 指令入口
- `di/dsl_*.go` — godi DSL 声明文件（`dsl_core.go` 核心服务、`dsl_anchor.go` 锚点、`dsl_inmemory.go` 内存存储扩展、`dsl_key_management.go` 密钥管理、`dsl_pluggable_services.go` 可插拔服务、`dsl_phone.go` / `dsl_wechat.go` 外部验证配置扩展点等）
- `di/server_config.go` — `ServerConfig` 运行时配置缝（宿主注入存储、客户端、密钥等）
- `di/inmemory.go` — 内存存储注册扩展
- `di/key_management.go` — 密钥管理服务注册
- `di/pluggable_services.go` — 可插拔服务注册
- `di/lifecycle.go` — 根生命周期（`CleanupExpired`、`Close` 资源释放）
- `di/container_gen.go` — godi-gen 生成物（禁止手编）

**生命周期模型：**
- Singleton：配置、时钟、数据保护、SchemeProvider
- Scoped：HttpContextAccessor、UserSession、AuthenticationService
- Transient：端点处理器、验证器、响应生成器

### 服务器入口（server/）

`Server` 结构体是宿主与 wicket 的唯一交互点：
- `UseWicket()` — 返回 `func(http.Handler) http.Handler` 中间件
- 中间件链：动态方案认证 → 核心认证 → 端点路由
- `Validate()` — 启动期装配校验（未注入 store 且未声明内存回退时启动失败）

### 端点路由（hosting/）

- `EndpointRouter` — 根据请求路径匹配已注册的 `Endpoint`
- `Middleware` — 拦截匹配请求，创建请求作用域，分发到 Handler
- `scope_middleware.go` — godi 请求作用域生命周期管理
- `dynamic/schemes.go` — 动态认证方案

### 协议处理器（handlers/）

每个 OIDC/OAuth 端点对应一个 Handler struct：
- 通过构造函数注入验证器、响应生成器、服务
- 实现 `Process` 方法处理 HTTP 请求
- Transient 生命周期，每请求创建
- 结果以 `handlers/results/` 中的 Result 类型表达（redirect、JSON、状态码等）

### 服务层（services/）

接口定义在 `services/interfaces.go`，实现在 `services/impl/`：
- `TokenService` / `TokenCreationService` — 令牌创建与序列化
- `RefreshTokenService` — 刷新令牌管理
- `ProfileService` / `ClaimsService` — 用户声明
- `ConsentService` / `InteractionService` — 用户交互
- `KeyMaterialService` — 密钥材料
- `UserSession` — 会话状态
- `SessionCoordinationService` — 服务端会话验证

### 存储层（storage/）

存储端口分三族，接口定义在 `storage/interfaces.go`、`session/session.go`、`keymgmt/record.go`，实现在 `storage/memory/`、`session/memory.go`、`keymgmt/store.go`：

- **storage 族**：`ClientStore`、`ResourceStore`、`AuthorizationCodeStore`、`RefreshTokenStore`、`ReferenceTokenStore`、`PersistedGrantStore`、`DeviceFlowStore`、`BackchannelAuthenticationRequestStore`、`UserConsentStore`、`SigningCredentialStore`、`ValidationKeysStore`、`AuthorizationParametersMessageStore`
- **session 族**：`session.Store` — 服务端会话记录（`SessionID` 键，按 subject 批量吊销）
- **keymgmt 族**：`keymgmt.RecordStore` — 签名密钥记录（乐观并发 + 四阶段生命周期）

每个端口都有 `ServerConfig` 注入缝，未注入时回退内存实现（生产装配须显式声明 `AllowInMemoryFallback()`，否则启动失败）。契约合规通过 `storagetest`、`sessiontest`、`keymgmttest` 三套件校验。

### 认证子系统（auth/）

- `auth/core/` — 认证服务核心（SchemeProvider、HandlerProvider、Middleware）
- `auth/cookies/` — Cookie 认证处理器
- `auth/google/` — Google OAuth 提供者
- `auth/facebook/` — Facebook OAuth 提供者
- `auth/jwt/` — JWT Bearer 认证
- `auth/oauth/core/` — OAuth 基础处理器 + PostConfigure
- `auth/openid/` — OpenID Connect 协议扩展

### 密钥管理（keymgmt/）

- `Manager` — 四阶段密钥生命周期（candidate → active → retained → retired），幂等轮换、单一签名选择规则
- `RecordStore` — 密钥记录持久化接口（乐观并发标记）
- `Protection` — 密钥加密保护
- 契约套件 `keymgmttest` 供适配器作者校验

### 外部令牌验证（oidcverify / wechatverify / phoneverify）

三包均为无状态验证能力，不参与 Web 授权码流、不依赖任何 store：

- `oidcverify` — 本地验签：用 JWKS 公钥验证外部 IdP 签发的 ID Token（Apple、Google 预设 + 自定义提供者）
- `wechatverify` — 服务端交换：微信移动应用授权 code 换跨应用用户标识（unionid/openid）
- `phoneverify` — 服务端交换：阿里号码认证 token 换手机号

## 请求处理流程

```
HTTP Request
    │
    ▼
hosting.Middleware（路径匹配）
    │
    ▼
godi 请求作用域创建
    │
    ▼
EndpointRouter.Resolve(path) → Endpoint
    │
    ▼
Handler.Process(w, r)
    │
    ├── validators（请求验证）
    ├── services（业务逻辑）
    ├── responses（响应生成）
    └── storage（持久化）
    │
    ▼
HTTP Response
```

## 配置体系

配置通过 `config/options/` 中的选项结构体管理：
- `WicketOptions` — 主配置（Issuer、端点路径、密钥管理、持久化授权、动态提供者）
- `auth.Options` — 认证方案配置
- `oauthcore.Options` — OAuth 基础配置
- `google.Options` / `facebook.Options` / `jwt.Options` — 外部提供者配置

选项通过 godi 的 `Options[T]` / `OptionsFactory[T]` / `OptionsMonitor[T]` 模式解析，支持 Configure → PostConfigure → Validate 管道。

## 测试策略

- **单元测试：** 直接构造被测 struct，不经 di/（`*_test.go`）
- **契约测试：** `storage/storagetest`、`session/sessiontest`、`keymgmt/keymgmttest` — 供适配器作者校验端口合规（含 `SuiteVersion` / `ConformsTo()` 版本凭证）
- **集成测试：** `test/integration/`，通过 `di.NewRoot()` 组装完整容器
- **端到端测试：** `tests/e2e/`，完整 HTTP 管道（本地发布窗口执行，不参与 CI）
- **测试辅助：** `test/common/`（mock/stub）、`test/integration/clients/setup/`（测试客户端配置）
