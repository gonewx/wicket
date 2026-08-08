# Wicket 源码树分析

## 目录结构

```
wicket/                          # Module: github.com/gonewx/wicket
├── go.mod                      # Module 声明；go 1.27（无 rc 指令）
├── go.work                     # Workspace（引用 ../godi，开发用，不入库）
├── go.work.sum                 # Workspace 校验和（不入库）
├── mise.toml                   # 工具链 pin（go = "1.27rc1"）
├── constants.go                # 全局常量（端点名、路由路径、scheme 名、grant type）
├── decorator.go                # 通用装饰器泛型
├── option.go                   # 函数选项模式辅助
├── token_request_constants.go  # 令牌请求常量
├── LICENSE                     # Apache 2.0
├── NOTICE                      # 归因通知
├── PROVENANCE.md               # Apache 血缘声明
├── CHANGELOG.md                # 版本变更记录
│
├── di/                         # 🔑 组合根（唯一装配点）
│   ├── root.go                 # go:generate 入口
│   ├── dsl_core.go             # 核心服务注册（端点、认证、选项）
│   ├── dsl_anchor.go           # 装配锚点
│   ├── dsl_additional.go       # 附加注册
│   ├── dsl_crypto.go           # 加密服务注册
│   ├── dsl_inmemory.go         # 内存存储注册扩展
│   ├── dsl_key_management.go   # 密钥管理注册
│   ├── dsl_message_cookie.go   # 消息 Cookie 注册
│   ├── dsl_oidcverify.go       # OIDC 验证器配置注册
│   ├── dsl_phone.go            # phoneverify 配置扩展点
│   ├── dsl_wechat.go           # wechatverify 配置扩展点
│   ├── dsl_options.go          # 选项基础设施
│   ├── dsl_pluggable_services.go # 可插拔服务注册
│   ├── server_config.go        # ServerConfig 运行时配置缝
│   ├── inmemory.go             # 内存存储注册
│   ├── key_management.go       # 密钥管理注册
│   ├── pluggable_services.go   # 可插拔服务注册
│   ├── lifecycle.go            # 根生命周期（清理、关闭）
│   ├── runtime_helpers.go      # 运行时辅助
│   ├── container_gen.go        # ⚠️ godi-gen 生成物（禁止手编）
│   └── options/                # 选项工厂/监视器泛型
│
├── server/                     # 🔑 服务器入口
│   ├── server.go               # Server struct + UseWicket() 中间件
│   └── authentication_service.go # 认证服务装配
│
├── hosting/                    # HTTP 托管层
│   ├── middleware.go           # 端点路由中间件
│   ├── endpoint_router.go      # 路径→端点匹配
│   ├── endpoint.go             # 端点元数据
│   ├── context.go              # 请求上下文扩展
│   ├── scope_middleware.go     # 请求作用域管理
│   └── dynamic/schemes.go      # 动态认证方案
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
├── storage/                    # 🔑 存储抽象层（端口族）
│   ├── interfaces.go          # 存储端口接口定义
│   ├── consent_message_store.go
│   ├── consent_message_key.go
│   ├── persisted_grant_filter.go
│   ├── impl/                  # 存储实现（消息存储、序列化器、令牌存储、客户端校验）
│   ├── memory/                # 内存存储（开发用默认）
│   ├── mock/                  # Mock（测试用）
│   ├── models/                # 存储模型（Client、Grant、Resource 等）
│   └── storagetest/           # 存储契约测试套件（适配器作者）
│
├── session/                    # 服务端会话端口族
│   ├── session.go             # Store 端口接口（会话 CRUD、按 subject 吊销、过期清理）
│   ├── memory.go              # 内存实现
│   └── sessiontest/           # 会话契约测试套件
│
├── keymgmt/                    # 密钥管理端口族
│   ├── manager.go             # 四阶段密钥生命周期（candidate/active/retained/retired）
│   ├── store.go               # 内存 RecordStore
│   ├── record.go              # RecordStore 端口 + 记录模型
│   ├── algorithm.go           # 算法选择
│   ├── protection.go          # 密钥保护
│   └── keymgmttest/           # 密钥记录契约测试套件
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
│   ├── token_validation_result.go
│   └── jwt/                   # JWT 令牌创建
│
├── auth/                       # 🔑 认证子系统
│   ├── core/                  # 认证核心（SchemeProvider、Middleware）
│   │   └── events/            # 认证事件
│   ├── cookies/               # Cookie 认证
│   ├── google/                # Google OAuth
│   ├── facebook/              # Facebook OAuth
│   ├── jwt/                   # JWT Bearer
│   ├── oauth/                 # OAuth 基础（core/ 处理器、claim action）
│   ├── openid/                # OIDC 协议扩展
│   │   └── protocols/
│   └── test/                  # 认证测试辅助
│
├── claims/                     # Claims 处理
├── client/                     # 客户端模型 + 发现端点
│   └── messages/
├── config/                     # 配置
│   └── options/               # 选项结构体
│       └── mock/
├── cookies/                    # Cookie 工具
├── dp/                         # 数据保护
├── dynamicscheme/              # 动态方案存储 + 解析
├── extensions/                 # 扩展方法
├── infrastructure/             # 基础设施（message_cookie.go）
├── oidcverify/                 # 外部 OIDC 令牌本地验签（无状态）
├── wechatverify/               # 微信授权 code 服务端交换（无状态）
├── phoneverify/                # 阿里号码认证服务端交换（无状态）
├── accessor/                   # HttpContext 访问器
├── utils/                      # 工具函数
│
├── test/                       # 测试
│   ├── common/                # 共享 mock/stub
│   ├── handlers/              # Handler 测试辅助
│   ├── resource_owner_validator.go
│   ├── test_user.go / test_user_store.go / test_user_profile_service.go
│   └── integration/           # 集成测试
│       ├── clients/setup/     # 测试客户端配置
│       ├── common/            # 集成测试辅助
│       ├── conformance/       # 协议一致性测试
│       ├── handlers/          # 端点集成测试
│       └── hosting/           # 托管层测试
│
├── tests/e2e/                  # 端到端测试（本地发布窗口执行，不参与 CI）
├── tools/                      # 工具（token_tools.go）
└── docs/                       # 项目文档
```

## 关键入口点

| 入口 | 路径 | 说明 |
|------|------|------|
| 服务器中间件 | `server/server.go:UseWicket()` | 宿主调用点 |
| 组合根 | `di/root.go` → `di/container_gen.go` | DI 装配 |
| 端点路由 | `hosting/endpoint_router.go` | 路径分发 |
| 配置缝 | `di/server_config.go` | 宿主注入运行时配置 |
| 存储端口 | `storage/interfaces.go` | 存储契约定义 |
| 会话端口 | `session/session.go` | 服务端会话契约 |
| 密钥端口 | `keymgmt/record.go` | 密钥记录契约 |

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

## 无状态验证包

`oidcverify` / `wechatverify` / `phoneverify` 独立于协议栈，不依赖任何 store，供业务后端直接调用：
- `oidcverify` — 本地 JWKS 验签（Apple / Google / 自定义 OIDC 提供者）
- `wechatverify` — 微信移动应用授权 code 换 unionid/openid（服务端交换）
- `phoneverify` — 阿里号码认证 token 换手机号（服务端交换）
