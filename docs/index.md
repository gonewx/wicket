# Wicket 项目文档索引

## 项目概览

- **类型：** 单体 Go 库
- **主语言：** Go 1.27rc1
- **架构：** 服务/API 驱动 + 依赖注入组合根
- **用途：** OpenID Connect / OAuth 2.0 身份认证服务器中间件

## 快速参考

- **Module：** `github.com/gonewx/wicket`
- **DI 框架：** godi（go.work workspace）
- **入口点：** `server.UseWicket()` → 中间件链
- **组合根：** `di/root.go` → `di/container_gen.go`
- **配置缝：** `di/server_config.go`（ServerConfig）

## 生成的文档

- [项目概览](./project-overview.md)
- [架构文档](./architecture.md)
- [源码树分析](./source-tree-analysis.md)
- [开发指南](./development-guide.md)
- [API 端点](./api-contracts.md)
- [外部认证提供者配置指南](./external-providers-guide.md)
- [存储持久化接入指南](./storage-persistence-guide.md) — 宿主如何装配持久化 store（规划中）

## 现有文档

- [PROVENANCE.md](../PROVENANCE.md) — Apache 2.0 血缘声明
- [NOTICE](../NOTICE) — 归因通知
- [LICENSE](../LICENSE) — Apache 2.0 许可证
- [project-context.md](../_bmad-output/project-context.md) — AI Agent 上下文规则

## 快速开始

```bash
# 1. 安装工具链
mise install

# 2. 构建
mise exec go@1.27rc1 -- go build ./...

# 3. 运行测试
mise exec go@1.27rc1 -- go test ./...

# 4. 代码生成（修改 di/ 后）
mise exec go@1.27rc1 -- go generate ./...
```

## 宿主集成示例

```go
root := di.NewRoot()
defer root.Close()

// 通过 ServerConfig 注入存储、客户端、密钥等
cfg := godi.GetRequired[*di.ServerConfig](root)
cfg.SetClients(...)
cfg.SetSigningCredentialStore(...)

srv := server.NewServer(root)
mux := http.NewServeMux()
mux.Handle("/", srv.UseWicket()(yourAppHandler))
http.ListenAndServe(":8080", mux)
```

---

*生成时间：2026-07-23 | 扫描模式：深度扫描 | 工作流版本：1.2.0*
