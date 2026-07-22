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
│  storage/           存储抽象层（接口 + 内存实现）           │
│  session/           服务端会话存储                        │
│  keymgmt/           密钥管理                             │
├─────────────────────────────────────────────────────────┤
│  di/                组合根（godi 装配 + 代码生成）         │
│  config/            配置选项体系                          │
└─────────────────────────────────────────────────────────┘
```

## 核心组件

### 组合根（di/）

- `di/root.go` — `//go:generate godi-gen` 指令入口
- `di/core.go` — 核心服务注册（端点路由、认证、选项、验证器、响应生成器）
- `di/server_config.go` — `ServerConfig` 运行时配置缝（宿主注入存储、客户端、密钥等）
- `di/inmemory.go` — 内存存储注册扩展
- `di/key_management.go` — 密钥管理服务注册
- `di/pluggable_services.go` — 可插拔服务注册
- `di/container_gen.go` — godi-gen 生成物（禁止手编）

**生命周期模型：**
- Singleton：配置、时钟、数据保护、SchemeProvider
- Scoped：HttpContextAccessor、UserSession、AuthenticationService
- Transient：端点处理器、验证器、响应生成器

### 服务器入口（server/）

`Server` 结构体是宿主与 wicket 的唯一交互点：
- `UseWicket()` — 返回 `func(http.Handler) http.Handler` 中间件
- 中间件链：动态方案认证 → 核心认证 → 端点路由

### 端点路由（hosting/）

- `EndpointRouter` — 根据请求路径匹配已注册的 `Endpoint`
- `Middleware` — 拦截匹配请求，创建请求作用域，分发到 Handler
- `scope_middleware.go` — godi 请求作用域生命周期管理

### 协议处理器（handlers/）

每个 OIDC/OAuth 端点对应一个 Handler struct：
- 通过构造函数注入验证器、响应生成器、服务
- 实现 `ProcessRequest` 方法处理 HTTP 请求
- Transient 生命周期，每请求创建

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

接口定义在 `storage/interfaces.go`，实现在 `storage/impl/` 和 `storage/memory/`：
- `ClientStore` — 客户端注册
- `ResourceStore` — API/Identity 资源
- `PersistedGrantStore` — 授权码、刷新令牌、引用令牌
- `DeviceFlowStore` — 设备流
- `BackchannelAuthenticationRequestStore` — CIBA
- `SigningCredentialStore` / `ValidationKeysStore` — 密钥材料
- `UserConsentStore` — 用户同意

### 认证子系统（auth/）

- `auth/core/` — 认证服务核心（SchemeProvider、HandlerProvider、Middleware）
- `auth/cookies/` — Cookie 认证处理器
- `auth/google/` — Google OAuth 提供者
- `auth/facebook/` — Facebook OAuth 提供者
- `auth/jwt/` — JWT Bearer 认证
- `auth/oauth/core/` — OAuth 基础处理器 + PostConfigure
- `auth/openid/` — OpenID Connect 协议扩展

### 密钥管理（keymgmt/）

- `Manager` — 密钥生命周期管理（生成、轮换、过期）
- `Store` — 密钥持久化接口
- `Protection` — 密钥加密保护

### 外部 OIDC 验证（oidcverify/）

- `Verifier` — 验证外部 IdP 签发的 OIDC 令牌
- 支持 Apple、Google 提供者预设
- 多受众验证

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
Handler.ProcessRequest(w, r)
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
- **集成测试：** `test/integration/`，通过 `di.NewRoot()` 组装完整容器
- **端到端测试：** `tests/e2e/`，完整 HTTP 管道
- **测试辅助：** `test/common/`（mock/stub）、`test/integration/clients/setup/`（测试客户端配置）
