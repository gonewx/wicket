# Wicket 开发指南

## 前置条件

| 工具 | 版本 | 说明 |
|------|------|------|
| Go | 1.27（跟随最新补丁版） | 通过 mise 管理 |
| mise | 最新 | 工具版本管理器 |
| godi-gen | 与 godi 同步（`go.mod` 的 `tool` 指令锁定） | DI 代码生成器，经 `go tool godi-gen` 调用 |

## 环境设置

```bash
# 安装 mise（如未安装）
curl https://mise.run | sh

# 安装项目锁定的 Go 版本
mise install

# 验证
mise exec -- go version
```

## 构建命令

所有 Go 命令必须通过 mise 调用，确保使用正确版本：

```bash
# 代码生成（修改 di/ 装配后必须执行）
# 生成指令自带 GOWORK=off：在 go.work 下生成器会把版本戳写成 (devel)，与 go.mod 漂移
mise exec -- go generate ./...

# 构建
mise exec -- go build ./...

# 运行全部测试
mise exec -- go test ./...

# 运行集成测试
mise exec -- go test -tags=integration ./...
```

## 提交前门禁

每次提交前必须运行以下三命令，全部通过方可提交：

```bash
mise exec -- go generate ./...
mise exec -- go build ./...
mise exec -- go test ./...
```

**漂移门禁：** `go generate` 后 `git status --porcelain` 必须为空。如果 `di/container_gen.go` 出现未提交修改，说明装配漂移，构建视为失败。

**缓存纪律（工具链版本变更后必读）：** `go test` 会复用构建缓存，输出 `(cached)` 的包并未重新编译。若缓存中残留的是旧工具链编译的产物，「全绿」只反映旧工具链下的结论，不能证明新工具链可用。因此**抬升或切换 Go 版本后的首轮验证，必须以 `go clean -cache` 起步，或全程加 `-count=1`**；发布窗口的绿跑记录应注明是否清过缓存。

判断缓存是否被污染的信号：编译时逐包报 `compile: version "goX" does not match go tool version "goY"`。

## 持续集成

GitHub Actions（`.github/workflows/ci.yml`）在每次 push 与 pull request 上自动承载门禁，作为合并阻塞条件。CI 为干净检出，与本地门禁等价：

| 阶段 | 内容 |
|------|------|
| 工具链 | mise 安装 `mise.toml` pin 的版本（当前 `go = "1.27"`，解析为已安装的最新 1.27.x 补丁版），不使用运行器自带 Go |
| 漂移门禁 | `go generate ./...` 后 `git status --porcelain` 必须为空 |
| 构建 | `go build ./...` |
| 全量测试 | `go test ./...`（排除 `tests/e2e` 包，见下） |
| 血缘门禁 | `go test ./tests/e2e/...`（整包，含溯源、命名卫生与协议回归）——**本地发布窗口执行，不参与 CI** |

**证据仓兄弟布局：** `tests/e2e` 的溯源类测试要求私有证据仓检出为本仓的兄弟目录（名称约定见 `tests/e2e/source_provenance_ledger_test.go` 的 `evidenceRepositoryRoot`；需要完整 git 历史，非 shallow），找不到即失败、无降级。**该证据仓凭据与历史均不进入 CI**：CI 不检出证据仓、也不运行 `tests/e2e` 包（`go test` 命令显式排除整包）；血缘门禁在本地发布窗口（如发版前）执行，CI 侧仅保留编译级覆盖（`go vet ./tests/e2e/...`）以捕获包内 API 漂移导致的编译断裂。

**CI 与本地门禁的关系：** CI 为干净检出，不受本地工具态目录影响；本地主工作树可能含工具态伪影（例如 `.rnix/` 下的缓存文件），个别命名规范类测试的跳过目录集较窄，可能据此误伤。本地需要全量验证时，用 `git worktree add` 建干净 worktree、在兄弟位置放置证据仓后复跑上述命令（含 `go test ./tests/e2e/...` 血缘门禁）。

## 开发工作流

### BMad Story 循环

所有功能开发遵循：`bmad-create-story` → `bmad-dev-story` → `bmad-code-review` → 合入。

### 判别力自证纪律

新增或改写守卫类测试后，须证明它真的能失败：反转被断言的条件，确认转红并给出预期消息，再还原。两条硬要求：

1. **反转配置文件前先停掉所有有写权限的 agent。** 曾发生自证期间临时改动的 `mise.toml` 中间态被写回源文件（`go@1.27.0` 被回退为 `go@1.27rc1`），靠 `git status` 才发现。
2. **收尾以 `git diff` 全量复核为准，不得只看测试绿。** 「输出看起来正常」不等于验证通过——命令因配置错误中止时也没有失败行、`(cached)` 命中也显示 `ok`、管道末端的 `tail` 退出码会掩盖前面命令的真实失败。判断依据只能是真实退出码与实际内容。

### 提交规范（Conventional Commits）

```
type(scope): description
```

- **type：** `feat`、`fix`、`refactor`、`test`、`docs`、`chore`
- **scope：** 对齐包名（`di`、`session`、`keymgmt`、`handlers`、`auth`）
- 提交信息保持功能中性，不记录过程元数据

### DI 装配修改流程

1. 修改 `di/` 中的注册代码
2. 运行 `mise exec -- go generate ./...`
3. 确认 `di/container_gen.go` 已更新
4. 运行构建和测试
5. 一起提交注册代码和生成物

### 测试组织

| 级别 | 位置 | 构造方式 | 说明 |
|------|------|----------|------|
| 单元测试 | 各包 `*_test.go` | 直接构造 struct | 快速反馈 |
| 集成测试 | `test/integration/` | `di.NewRoot()` + `t.Cleanup` | 完整容器 |
| 端到端 | `tests/e2e/` | 完整 HTTP 管道 | 协议一致性 |

**规则：**
- 单元测试和集成测试不得混用
- Mock/fake 只允许在单元测试内
- 新增测试用 table-driven（`map[string]struct{...}` + `t.Run`）
- 默认加 `t.Parallel()`（除非共享全局状态）
- 禁止 `time.Now()` / `rand.Read`，使用注入的 `clock.Clock` 与 `rand.Reader`

## 关键约束

- **`di/container_gen.go` 禁止手编** — 它是生成物
- **不引入额外外部依赖** — Go 标准库足够覆盖的场景不引第三方
- **接口放消费侧** — 不集中在 `interfaces/` 目录
- **配置通过 ServerConfig 缝注入** — 业务包不用 `os.Getenv` / 全局变量
- **导入路径一律 `github.com/gonewx/wicket/...`**
- **一切命令经 `mise exec`** — PATH 上的裸 `go` 可能指向另一个版本（本项目在 1.27.0 抬升时点实测为遗留的 `1.27rc1`），直接敲 `go build` / `go test` 会用错工具链，而声明文件仍然全绿。自查：比较 `which go` 与 `mise which go` 是否一致。`tests/e2e` 的工具链守卫会断言实际运行版本满足 `mise.toml` 的 pin（`1.27` 接受任意 1.27.x 正式版，拒绝 rc），忘记 `mise exec` 时它会转红并提示。

## 常用开发任务

### 添加新端点

1. 在 `handlers/` 创建 Handler struct
2. 在 `di/dsl_core.go` 注册 Endpoint 元数据 + Handler 工厂
3. 运行 `go generate ./...`
4. 添加集成测试到 `test/integration/handlers/`

### 添加新服务

1. 在 `services/interfaces.go` 定义接口
2. 在 `services/impl/` 实现
3. 在 `di/` 注册（选择正确生命周期）
4. 运行 `go generate ./...`

### 添加新存储

1. 在 `storage/interfaces.go` 定义接口
2. 在 `storage/impl/` 或 `storage/memory/` 实现
3. 通过 `ServerConfig` 缝或 `di/inmemory.go` 注册
