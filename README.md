# WatchApi Rust

WatchApi Rust 是一个当前主要面向 Codex 的接口管理和自动续航工具。
它可以统一管理多个 OpenAI 兼容接口，自动探测可用性、按权重选择线路、处理冷却/限流，并在 Agent 中断或无进展时按配置继续任务。

> 兼容性说明：作者目前只使用 Codex 做过完整测试；Claude Code、OpenCode 等其它 Agent 的适配仍在完善中，暂不保证达到 Codex 同等体验。

用户使用说明见 [docs/USER_MANUAL.md](docs/USER_MANUAL.md)。

## 功能概览

- `watchapi-core`：配置读取、HTTP 探测、models 缓存、最便宜探测模型选择、健康状态、权重选择、污染阈值、额度识别、token/费用格式化、Codex 配置写入、session 基础恢复、终端 PTY 抽象、运行循环。
- `watchapi-core` 的 Codex 启动会使用临时隔离的 `CODEX_HOME`，并通过 CLI `-c` 覆盖模型、provider、base_url、权限、审批策略和 TUI 状态栏信息，避免多个 Codex 会话互相改同一个真实 `~/.codex/config.toml` / `auth.json`；停止时会把临时 session 记录合并回真实 Codex Home。
- `watchapi-gui`：`eframe/egui` 轻量 GUI，可选择/加载/编辑 JSON 配置、保存到 exe 同级 `Configs`、维护提示词库、配置列表/别名/克隆/移除/自启动、启动/停止/全部启动/全部停止、暂停/继续自动续航、立即触发、日志写入/搜索、显示接口组表格、显示终端输出，并把用户输入直接写入 PTY。
- `watchapi-gui` 的“聚合代理”页支持多个本地 LiteLLM 代理端口、多个上游 URL、批量 txt/csv Key、模型路由、生成 LiteLLM 配置、启动/停止代理，并在 GUI 退出时清理代理进程。
- GUI 关闭窗口时会先询问：进入系统托盘后台运行、直接关闭、取消。托盘菜单支持“显示 WatchApi”和“退出 WatchApi”；托盘不可用时会降级为最小化到任务栏。
- `watchapi-cli`：提供命令行 watch 模式和本地 HTTP/HTTPS upstream 中转代理；`Ctrl+C` 会先停止运行时并恢复 Codex 配置/key。
- 终端输入：用户手动输入和自动提示词共用同一个 PTY stdin writer；当用户正在输入时，自动提示词会被 `UserInputActive` 阻塞，避免抢输入。

## 工作区结构

```text
watchapi-core/   核心配置、探测、运行时、终端和自动续航逻辑
watchapi-gui/    桌面 GUI、托盘、供应商库和 LiteLLM 代理管理
watchapi-cli/    命令行 watch 和本地代理入口
vendor/          固定版本的 portable-pty 依赖
.package-cache/  离线 LiteLLM 打包缓存
docs/            用户文档
```

## 开发命令

运行测试：

```powershell
cd rust
cargo test --workspace
```

运行 GUI 骨架：

```powershell
cd rust
cargo run -p watchapi-gui
```

直接加载配置启动 GUI：

```powershell
cd rust
cargo run -p watchapi-gui -- --config ..\Configs\你的配置.json
```

命令行 watch：

```powershell
cd rust
cargo run -p watchapi-cli -- watch --config ..\Configs\你的配置.json
```

本地中转代理：

```powershell
cd rust
cargo run -p watchapi-cli -- proxy --listen 127.0.0.1:8787 --upstream https://api.example.com --key sk-xxx
```

## 发布打包

release 构建产物：

```text
rust\target\release\watchapi-gui.exe
rust\target\release\watchapi-cli.exe
```

打包 portable 目录和 zip：

```powershell
cd rust
.\package-release.ps1
```

打包完全离线 LiteLLM portable 包：

```powershell
cd rust
.\package-release.ps1 -BundleLiteLLMOffline
```

这个模式会把 Python embeddable、LiteLLM Proxy 及依赖安装到发布目录的 `LiteLLM` 下。首次打包需要网络下载 Python embeddable 和 wheels，缓存位置是 `rust\.package-cache`；之后可复用缓存生成离线发布包。发布后的目标电脑不需要额外安装 Python、pip 或 LiteLLM。

默认输出：

```text
dist\WatchApiRust-portable\
dist\WatchApiRust-portable.zip
```

GUI 首次新建配置会默认保存到 exe 同级 `Configs` 目录；提示词库保存在 exe 同级 `prompt-library.json`。

聚合代理配置保存在 exe 同级 `ProxyConfigs\proxies.json`，生成的 LiteLLM 配置和日志也在 `ProxyConfigs` 下。GUI 启动代理时会优先使用发布包内 `LiteLLM\litellm.cmd`；如果不存在，则回退到系统 PATH 里的 `litellm` 命令。
