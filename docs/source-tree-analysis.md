# Wicket 源码树分析

## 目录结构

```
wicket/
├── go.mod                      # Module: github.com/gonewx/wicket
├── go.work                     # Workspace（引用 ../godi，不入库）
├── mise.toml                   # Go 1.27rc1 版本锁定
├── constants.go                # 全局常量（端点名、路由路径、scheme 名）
├── decorator.go                # 通用装饰器泛型
├── option.go                   # 函数选项模式辅助
├── token_request_constants.go  # 令牌请求常量
├── LICENSE                     # Apache 2.0
├── NOTICE                      # 归因通知
├── PROVENANCE.md               # Apache 血缘声明
│
├── di/                         # 🔑 组合根（唯一装配点）
│   ├── root.go                 # go:generate 入口
│   ├── core.go                 # 核心服务注册（端点、认证、选项）
│   ├── server_config.go        # ServerConfig 运行时配置缝
│   ├── inmemory.go             # 内存存储注册扩展
│   ├── key_management.go       # 密钥管理注册
│   ├── pluggable_services.go   # 可插拔服务注册
│   ├── additional.go           # 附加注册
│   ├── crypto.go               # 加密服务注册
│   ├── message_cookie.go       # 消息 Cookie 注册
│   ├── oidcverify.go           # OIDC 验证器注册
│   ├── options.go              # 选项基础设施
│   ├── runtime_helpers.go      # 运行时辅助
│   ├── container_gen.go        # ⚠️ godi-gen 生成物（禁止手编）
│   └── options/                # 选项工厂/监视器泛型
│
├── server/                     # 🔑 服务器入口
│   └── server.go               # Server struct + UseWicket() 中间件
│
├── hosting/                    # HTTP 托管层
│   ├── middleware.go           # 端点路由中间件
│   ├── endpoint_router.go     # 路径→端点匹配
│   ├── endpoint.go            # 端点元数据
│   ├── context.go             # 请求上下文扩展
│   ├── scope_middleware.go    # 请求作用域管理
│   └── dynamic/schemes/       # 动态认证方案
│
├── handlers/                   # 🔑 协议端点处理器
│   ├── authorize_handler.go
│   ├── authorize_callback_handler.go
│   ├── authorize_base_handler.go
│   ├── token_handler.go
│   ├── discovery_handler.go
│   ├── discovery_key_handler.go
│   ├── user_info_handler.go
│   ├── introspection_handler.go
│   ├── end_session_handler.go
│   ├── end_session_callback_handler.go
│   ├── check_session_handler.go
│   ├── backchannel_authentication.go
│   └── results/               # 处理器结果类型
│
├── services/                   # 🔑 业务服务层
│   ├── interfaces.go          # 所有服务接口定义
│   ├── return_url_parser.go
│   ├── logout_notification_service.go
│   ├── back_channel_logout_http_client.go
│   ├── impl/                  # 服务实现
│   ├── memory/                # 内存实现
│   └── mock/                  # Mock（测试用）
│
├── storage/                    # 🔑 存储抽象层
│   ├── interfaces.go          # 所有存储接口定义
│   ├── consent_message_store.go
│   ├── consent_message_key.go
│   ├── persisted_grant_filter.go
│   ├── impl/                  # 存储实现
│   ├── memory/                # 内存存储
│   ├── mock/                  # Mock（测试用）
│   └── models/                # 存储模型（Client、Grant、Resource 等）
│
├── validators/                 # 请求/令牌验证
│   ├── impl/                  # 验证器实现
│   ├── contexts/              # 验证上下文
│   ├── models/                # 验证结果模型
│   └── mock/                  # Mock
│
├── responses/                  # 响应生成
│   ├── impl/                  # 响应生成器实现
│   └── models/                # 响应模型
│
├── models/                     # 领域模型
│   ├── grant.go
│   ├── local_user.go
│   ├── parsed_secret.go
│   ├── authentication_properties.go
│   ├── security_key_info.go
│   ├── json_web_key.go
│   ├── contexts/              # 业务上下文
│   └── messages/              # 协议消息
│
├── tokens/                     # 令牌模型
│   ├── signing.go             # 签名凭据
│   └── token_validation_result.go
│   └── jwt/                   # JWT 令牌创建
│
├── keymgmt/                    # 密钥管理
│   ├── manager.go             # 密钥生命周期
│   ├── store.go               # 密钥存储接口
│   ├── record.go              # 密钥记录
│   ├── algorithm.go           # 算法选择
│   └── protection.go          # 密钥保护
│
├── session/                    # 服务端会话
│   ├── session.go             # 会话存储接口
│   └── memory.go              # 内存实现
│
├── auth/                       # 🔑 认证子系统
│   ├── core/                  # 认证核心（SchemeProvider、Middleware）
│   │   └── events/            # 认证事件
│   ├── cookies/               # Cookie 认证
│   ├── google/                # Google OAuth
│   ├── facebook/              # Facebook OAuth
│   ├── jwt/                   # JWT Bearer
│   ├── oauth/core/            # OAuth 基础处理器
│   ├── openid/                # OIDC 协议扩展
│   │   └── protocols/
│   └── test/                  # 认证测试辅助
│
├── claims/                     # Claims 处理
├── client/                     # 客户端模型 + 消息
│   └── messages/
├── config/                     # 配置
│   └── options/               # 选项结构体
│       └── mock/
├── cookies/                    # Cookie 工具
├── dp/                         # 数据保护
├── dynamicscheme/              # 动态方案存储 + 解析
├── extensions/                 # 扩展方法
├── infrastructure/             # 基础设施
├── oidcverify/                 # 外部 OIDC 令牌验证
├── accessor/                   # HttpContext 访问器
├── utils/                      # 工具函数
│
├── test/                       # 测试
│   ├── common/                # 共享 mock/stub
│   ├── handlers/              # Handler 测试辅助
│   └── integration/           # 集成测试
│       ├── clients/setup/     # 测试客户端配置
│       ├── common/            # 集成测试辅助
│       ├── conformance/       # 协议一致性测试
│       ├── handlers/          # 端点集成测试
│       └── hosting/           # 托管层测试
│
├── tests/e2e/                  # 端到端测试
├── tools/                      # 工具
└── docs/                       # 项目文档
```

## 关键入口点

| 入口 | 路径 | 说明 |
|------|------|------|
| 服务器中间件 | `server/server.go:UseWicket()` | 宿主调用点 |
| 组合根 | `di/root.go` → `di/container_gen.go` | DI 装配 |
| 端点路由 | `hosting/endpoint_router.go` | 路径分发 |
| 配置缝 | `di/server_config.go` | 宿主注入运行时配置 |

## 包依赖方向

```
server → hosting → handlers → validators/responses/services → storage/models
                                    ↓
                              auth (外部 IdP)
                                    ↓
                         tokens / keymgmt / session
                                    ↓
                              di (组合根，反向装配)
```
