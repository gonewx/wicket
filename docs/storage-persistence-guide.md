# 存储持久化接入指南

> 状态：**目标形态已落地**。存储端口契约、契约测试套件与注入缝均已定型；首个发布版本 `v0.1.0` 发布后，适配器仓即可直接 `require github.com/gonewx/wicket`。
> 权威约束见 [ARCHITECTURE-SPINE](../_bmad-output/planning-artifacts/architecture/architecture-wicket-2026-07-31/ARCHITECTURE-SPINE.md)（AD-2 至 AD-14）。

## 概述

wicket 的存储端口分三族，职责与持久化必要性各不相同：

| 端口族 | 位置 | 存的是什么 | 不持久化的后果 |
| --- | --- | --- | --- |
| `storage` | `storage/interfaces.go` | 授权码、refresh token、reference token、用户同意、grant、设备码 | 进程重启后已签发的 refresh token 全部失效；多副本部署下授权码换令牌随机失败 |
| `session` | `session/` | 服务端会话记录 | 重启即全员登出；多副本下会话不共享 |
| `keymgmt` | `keymgmt/` | 签名密钥及其轮换状态 | 每次重启换签名密钥，已签发的 JWT 全部验签失败 |

**只用外部凭据验签的宿主不受影响。** `oidcverify` / `wechatverify` / `phoneverify` 三个包无状态、不依赖任何 store（AD-13）。若你的应用只需"客户端拿到 Apple/Google/微信令牌，后端验签换取本地身份"，可以完全不装配 store，也不需要读本文余下部分。

## 何时需要持久化

需要：以完整 OIDC 授权服务器形态部署——对外暴露 `/connect/authorize`、`/connect/token` 端点，服务第三方 client，或需要跨应用 SSO、Web 授权码流、服务端会话。

不需要：仅使用外部 IdP 验签能力（见上）。此时 wicketserver 的 quickstart 装配形态即可参考。

## 分层职责

```
宿主应用
    │
    ├── 提供基础设施句柄（连接池、DSN）
    ├── 执行适配器仓的迁移
    ├── 构造适配器实例 → 注入 ServerConfig
    └── 驱动清理循环（wicket 不自起后台任务）
    │
    ↓
适配器平级仓（如 PostgreSQL 适配器）
    │
    ├── 实现 wicket 的 store 端口
    ├── 自有 migrations（表所有权归适配器仓）
    └── 通过 storagetest 契约套件，暴露 ConformsTo()
    │
    ↓
wicket 主模块
    │
    ├── 定义端口接口与契约语义
    ├── 提供内存默认实现（开发用）
    └── 提供 storagetest 契约套件
```

三条边界规则：

- **wicket 主模块零数据库依赖**（AD-2）。持久化实现一律在平级仓，这样只用验签能力的宿主不会继承 Postgres 驱动。
- **宿主不实现 store**（AD-7）。现有适配器不敷使用时，向适配器仓贡献或新建适配器仓，而不是在宿主里写一份。
- **表所有权归适配器仓**。迁移文件随适配器分发，宿主只负责按序执行。

## 宿主装配

### 注入 store

每个 store 端口都有 `ServerConfig` 注入缝，未注入则回退内存实现：

```go
cfg := di.NewServerConfig()

cfg.SetAuthorizationCodeStore(pgadapter.NewAuthorizationCodeStore(pool))
cfg.SetRefreshTokenStore(pgadapter.NewRefreshTokenStore(pool))
cfg.SetReferenceTokenStore(pgadapter.NewReferenceTokenStore(pool))
cfg.SetUserConsentStore(pgadapter.NewUserConsentStore(pool))
cfg.SetPersistedGrantStore(pgadapter.NewPersistedGrantStore(pool))
cfg.SetDeviceFlowStore(pgadapter.NewDeviceFlowStore(pool))
cfg.SetSessionStore(pgadapter.NewSessionStore(pool))
cfg.SetKeyRecordStore(pgadapter.NewKeyRecordStore(pool))
```

### 禁止混合注入

生产装配下**未注入的 store 应启动即失败**，而不是静默回退内存（AD-4）。混合注入会造出一个多副本下必然失败的系统：授权码在节点 1 的内存里，token 请求打到节点 2 就查不到，用户看到随机的登录失败。

开发模式下若确实要用内存实现，须显式声明：

```go
// 仅开发环境 —— 生产装配省略此调用，未注入的 store 会导致启动失败
cfg.AllowInMemoryFallback()
```

### 驱动清理

wicket **不自起后台 goroutine**（AD-12），过期数据的清理由宿主按自身调度驱动：

```go
ticker := time.NewTicker(10 * time.Minute)
defer ticker.Stop()
for {
    select {
    case <-ticker.C:
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        if err := root.CleanupExpired(ctx); err != nil {
            logger.Error("cleanup failed", "err", err)
        }
        cancel()
    case <-shutdown:
        return
    }
}
```

清理只回收空间，**不承担正确性**——过期判定始终在 wicket 核心侧完成（AD-3 要素 6）。

### 释放资源

适配器持有的连接池在 `Root.Close()` 路径上释放：

```go
defer root.Close()
```

## 校验适配器合规性

适配器必须通过 wicket 的契约测试套件，并暴露版本凭证（AD-6）。装配时校验：

```go
if got := adapter.ConformsTo(); got != storagetest.SuiteVersion {
    log.Fatalf("适配器契约版本不匹配: 适配器=%s, wicket 要求=%s", got, storagetest.SuiteVersion)
}
```

没有 `ConformsTo()` 的实现不是合规适配器——它可能连契约套件都没跑过，或者 `t.Skip()` 掉了一半用例。

## 存储契约要点

宿主一般不需要关心这些细节，但理解它们有助于判断适配器质量、以及排查换介质后的行为差异。完整定义见 AD-3。

**"不存在"与"故障"必须可区分。** store 在记录不存在时返回 `ErrNotFound` 哨兵，绝不返回 `(nil, nil)`。这条很要紧：若二者混为一谈，一次数据库网络抖动会被当成"凭证无效"，用户看到登录失败而日志里没有任何告警。

**写入默认 insert-only。** 句柄碰撞返回 `ErrDuplicateHandle`。refresh token 轮换的重放防线依赖这个语义——若某个适配器实现成 upsert（如 Redis 的 `SET` 天然覆盖），防线会静默失效。

**并发更新需要版本号。** 读-改-写类更新携带 `expectedVersion`，冲突返回 `ErrVersionConflict`。宿主侧一般由 wicket 核心处理重试，不需要自己写循环。

**超时由调用方决定。** 每个 store 方法首参为 `context.Context`，适配器不得自设超时覆盖。你在 HTTP handler 里设的 deadline 会一路传到数据库查询。

**过期判定在核心侧。** 适配器**不得**在查询里加 `expires_at > now()` 之类的过滤。理由是集群里数据库时钟与应用节点时钟会漂移，两处判定得出不同结论；统一在核心侧用注入的 `Clock` 判定才可控。

## 编写适配器

若要为新介质编写适配器，最低要求：

1. **独立仓** `require github.com/gonewx/wicket`，实现所需 store 端口。
2. **通过契约套件** —— 引入 `storage/storagetest`，跑全部 MUST 级用例，容器/夹具自备。
3. **暴露 `ConformsTo()`** 返回所依据的 `storagetest.SuiteVersion`。
4. **自备迁移** —— 表所有权归你的仓。
5. **血缘门禁** —— 移植 wicket 的等效门禁（文件头归属断言、禁上游血缘标注、commit message 扫描）。跨仓不等于免除血缘纪律（AD-14）。
6. **LICENSE / NOTICE / PROVENANCE** —— 新仓属独立实现模块，须自备三件套并留独立设计记录。

**schema 独立设计**（AD-10）：表结构须从 wicket 端口的读写访问模式推导——按句柄取用、按 subject 批量吊销、按过期时间清理——而不是逐一映射 `storage/models/*.go` 的字段（那些 model 带上游 Apache 血缘）。留存设计记录说明每张表、每个索引对应哪条端口方法。序列化载荷沿用 `PersistentGrantDataContainer` 的版本容器形态以单列存储。列名的 snake_case 转写属语言惯例，但禁止照搬上游 EntityFramework 的表名、实体划分与列集合。

**日志与凭据**（AD-12）：日志经注入的 `*slog.Logger`，不自建 logger 或写 stdout。**禁止**把令牌值、句柄、密钥、client secret 写入任何级别的日志——只记其存在性与标识符前缀。

## 当前状态与前置条件

本文所述形态的落地依赖一条不可颠倒的顺序链（AD-8），自首版发布起已全部达成：

```
godi 建远端托管 → godi 发版 → 进 wicket go.mod → 清 go.work 遗留
  → AD-3 契约修正 + AD-4 注入缝统一 + AD-11 句柄职责收敛
  → storagetest 契约套件 → 血缘证据链核验 → Go 1.27 正式版
  → wicket v0.x 首个 tag → 适配器仓 require wicket
```

已解除的前置：

- `github.com/gonewx/godi` 已发布 `v0.1.0` 并入 `go.mod`，wicket 可被外部 `go get`。
- `go.mod` 已切 `go 1.27` 无 rc directive；首个 tag 不携带 rc。

**适配器仓已建骨架。** `github.com/gonewx/wicket-pg`（module `github.com/gonewx/wicket-pg`）为 PostgreSQL 适配器的独立骨架仓，已含 LICENSE、PROVENANCE、交接说明 HANDOFF.md 与三项血缘门禁（文件头归属断言、禁上游血缘标注、commit message 扫描）。适配器实现、schema 与迁移属该仓范围，按 HANDOFF.md 中的后续步骤执行（第 1 步为 `require wicket` 首个 semver tag）。

## 相关文档

- [ARCHITECTURE-SPINE](../_bmad-output/planning-artifacts/architecture/architecture-wicket-2026-07-31/ARCHITECTURE-SPINE.md) — 权威架构约束
- [架构文档](./architecture.md) — 整体架构
- [外部认证提供者配置指南](./external-providers-guide.md) — 无状态验签路径（不需要 store）
- [开发指南](./development-guide.md) — 构建与测试
- [PROVENANCE.md](../PROVENANCE.md) — 血缘声明与桶归属
