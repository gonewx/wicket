# Wicket 项目概览

## 项目简介

Wicket 是一个用 Go 编写的 OpenID Connect (OIDC) / OAuth 2.0 身份认证服务器库。它作为中间件嵌入宿主 HTTP 应用，提供完整的协议端点（授权、令牌、发现、用户信息、会话管理、CIBA 等），支持多种外部身份提供者（Google、Facebook、Apple）和 JWT Bearer 认证。

## 技术栈摘要

| 类别 | 技术 | 版本 | 说明 |
|------|------|------|------|
| 语言 | Go | 1.27.0（mise pin `1.27.0`） | 通过 mise 管理；`go.mod` 声明 `go 1.27`（无 rc 指令） |
| Module | `github.com/gonewx/wicket` | — | 库模式，非独立可执行文件 |
| DI 框架 | `github.com/gonewx/godi` | v0.1.0 | 已发布，编译期代码生成；本地开发仍经 go.work 引用 |
| JWT | `github.com/lestrrat-go/jwx/v3` | 3.2.0 | 令牌签发与验证 |
| JSON 解析 | `github.com/tidwall/gjson` | 1.19.0 | 高性能 JSON 路径查询 |
| UUID | `github.com/google/uuid` | 1.6.0 | 唯一标识生成 |
| HTTP 客户端 | `github.com/lestrrat-go/httprc/v3` | 3.0.6 | JWKS 获取 |
| 号码认证 | `github.com/aliyun/alibaba-cloud-sdk-go` | 1.63.107 | 仅 `services/dypnsapi` 与 `sdk/errors`，封装于 `phoneverify` |
| 测试断言 | `github.com/stretchr/testify` | 1.11.1 | 仅测试依赖 |
| 许可证 | Apache 2.0 | — | 含 IS4 Apache 血缘归因 |

## 架构类型

- **仓库类型：** 单体（Monolith）
- **架构模式：** 服务/API 驱动 + 依赖注入组合根
- **设计哲学：** 接口定义在消费侧（依赖倒置），godi 组合根统一装配，ServerConfig 提供运行时配置缝

## 核心能力

- OIDC 授权码流（含 PKCE）
- OAuth 2.0 令牌端点（authorization_code、refresh_token、client_credentials、device_code、CIBA）
- OpenID Connect Discovery（`.well-known/openid-configuration`、JWKS）
- 用户信息端点
- 令牌内省（Introspection）
- 会话管理（CheckSession、EndSession）
- CIBA（Client Initiated Backchannel Authentication）
- 设备授权流（Device Flow）
- 外部 IdP 集成（Google、Facebook、Apple、JWT Bearer）
- 动态认证方案（运行时注册外部提供者）
- 密钥管理（四阶段签名密钥生命周期：candidate → active → retained → retired）
- 服务端会话存储
- 外部令牌验证三件套：`oidcverify`（本地验签）、`wechatverify`（微信服务端交换）、`phoneverify`（阿里号码认证服务端交换）
- 存储契约测试套件：`storagetest`、`sessiontest`、`keymgmttest`（适配器作者合规依据）

## 仓库结构

```
wicket/                  # Go 库根目录
├── di/                  # 组合根（godi 装配，dsl_*.go 声明 + 生成物）
├── server/              # Server 入口 + 中间件组装
├── hosting/             # HTTP 中间件 + 端点路由
├── handlers/            # 协议端点处理器
├── services/            # 业务服务接口 + 实现
├── storage/             # 存储抽象接口 + 内存实现 + storagetest 契约套件
├── validators/          # 请求/令牌验证器
├── responses/           # 响应生成器
├── models/              # 领域模型
├── tokens/              # 令牌模型 + 签名
├── keymgmt/             # 密钥管理 + keymgmttest 契约套件
├── session/             # 服务端会话 + sessiontest 契约套件
├── auth/                # 认证抽象 + 外部 IdP
├── claims/              # Claims 处理
├── config/              # 配置选项
├── oidcverify/          # 外部 OIDC 令牌本地验签
├── wechatverify/        # 微信授权 code 服务端交换
├── phoneverify/         # 阿里号码认证服务端交换
├── dynamicscheme/       # 动态认证方案存储 + 解析
├── test/                # 集成测试 + 测试辅助
├── tests/e2e/           # 端到端测试（本地发布窗口执行）
└── docs/                # 项目文档（本目录）
```

## 发布状态

- 已发布 `v0.1.0`、`v0.1.1`、`v0.1.2`（Go 1.27 工具链）
- 存储适配器：官方 PostgreSQL 适配器仓 `github.com/gonewx/wicket-pg`
- 详见 [存储持久化接入指南](./storage-persistence-guide.md) 与 [CHANGELOG](../CHANGELOG.md)
