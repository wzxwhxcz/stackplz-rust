# stackplz-rs

Rust 重构版 [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz) —— 一款基于 eBPF 的 Android 堆栈追踪工具。

**目标**：底层用 Rust 重写，所有用户可见行为与内核契约与原 Go 项目**逐字对齐**（CLI、配置文件、eBPF 程序、事件解码格式、栈回溯输出）。

## 与原项目的对照

| 维度 | 原 Go 项目 | 本 Rust 版 |
|------|-----------|-----------|
| CLI 框架 | `spf13/cobra` | `clap` v4 derive（开启 `infer_long_args` 复刻 cobra 前缀匹配） |
| eBPF 加载 | 魔改的 `cilium/ebpf` + `ehids/ebpfmanager` | `libbpf-rs` |
| 栈回溯 | cgo `dlopen` 预编译 `libstackplz.so`（基于 Android `libunwindstack`） | `libloading` dlopen **同一批** `preload_libs/*.so`，行为 100% 一致 |
| 资产嵌入 | `go-bindata` 生成 `assets` 包 | `include_bytes!`（`src/assets.rs`） |
| 配置 | `encoding/json` | `serde` / `serde_json` |
| ELF 符号解析 | `ebpfmanager` 内部 | `object` crate |

不变的内核契约（Rust 侧用 `#[repr(C)]` + 小端严格对齐，带单元测试断言字节布局）：

- **`filter_map` 值**：`StackFilter` = 32 字节，`SyscallFilter` = 36 字节（多一个 `nr` 字段）
- **perf 事件载荷**：`u32 sample_size → u32 pid → u32 tid → u64 ts → char[16] comm`，syscall 尾部多 `i64 NR`，可选 `UnwindBuf`（abi + regs[33] + stack_size + data + dyn_size）
- **perf 采样参数**：`sample_regs_user = (1<<33)-1`、`sample_stack_user = 8192`
- **eBPF C 源**：`ebpf/{stack,raw_syscalls}.c` + `common.h` **原样复制**，未做任何改动

## 目录结构

```
stackplz-rs/
├── Cargo.toml
├── build.rs                # 用 clang 编译 ebpf/*.c -> ebpf/bpf/*.o
├── build_env.sh            # 拉取 AOSP 头文件到 external/
├── ebpf/                   # eBPF C 源（原样复制自上游）
│   ├── common.h
│   ├── stack.c
│   └── raw_syscalls.c
├── assets/preload_libs/    # 预编译 .so（原样复制自上游，9 个文件）
├── config.json             # 示例配置（原样复制）
└── src/
    ├── main.rs             # 入口：is_enable_bpf() -> cli::start()
    ├── assets.rs           # include_bytes! 嵌入 .so + restore_assets（--prepare）
    ├── logger.rs           # log.Ltime + MultiWriter 等价（stdout + file）
    ├── cli/                # clap CLI（args.rs）+ root/stack_cmd/syscall_cmd handlers
    ├── config/             # SConfig/GlobalConfig/TargetConfig/ProbeConfig/SyscallConfig + hook_json
    ├── ebpf/               # capability.rs（/proc/config.gz）+ bpf_common.rs（libbpf-rs 胶水）
    ├── event/              # ievent/context/hook/syscall_event + unwind_ffi（dlopen get_stack）
    ├── module/             # stack_probe（uprobe）+ syscall_tracepoint（tracepoint）
    └── util/               # hexdump + fs（FindLib/ReadMapsByPid）+ reg（ParseReg）
```

## 构建

> **环境**：必须在 Linux/WSL 上构建，目标是 Android arm64。

1. **拉取 AOSP 头文件**（只需一次）：
   ```bash
   ./build_env.sh
   ```
2. **安装 Rust Android target + libbpf**：
   ```bash
   rustup target add aarch64-linux-android
   # libbpf-rs 需要 libbpf 1.x：用 NDK 的 clang，或系统安装 libbpf-dev
   ```
3. **配置 NDK linker**（`~/.cargo/config.toml`）：
   ```toml
   [target.aarch64-linux-android]
   linker = "<NDK>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang"
   ```
4. **编译**（嵌入 eBPF 字节码）：
   ```bash
   cargo build --release --target aarch64-linux-android --features embedded_bpf
   ```
5. 产物在 `target/aarch64-linux-android/release/stackplz`，推到手机 `/data/local/tmp`。

## 使用

与原项目完全一致：

```bash
/data/local/tmp/stackplz stack --prepare          # 释放 preload_libs
./stackplz --name com.lemon.lv --pid 11267 syscall --nr 63 --regs --stack
./stackplz --uid 10245 stack --symbol open --stack --regs
./stackplz --name com.sfx.ebpf stack --library libnative-lib.so --symbol _Z5func1v --stack --regs
./stackplz --name com.sfx.ebpf stack --config config.json
```

## 当前状态

- ✅ 完整 CLI 表面（所有 flag/默认值/语义与原版对齐，`--help` 已对齐）
- ✅ 配置层（`config.json` 解析、`ProbeConfig::Check`、`filter_t` 字节布局单测）
- ✅ 事件解码（公共头 + `UnwindBuf`/`RegsBuf`，小端，单测）
- ✅ 栈回溯 FFI（`libloading` dlopen `libstackplz.so` 调 `get_stack`）
- ✅ util（`FindLib` / `ParseReg` / hexdump）
- ✅ 资产嵌入 + `--prepare` 释放
- ✅ build.rs 编译 eBPF + NDK 交叉编译文档
- ⚠️ **perf 采样攻关**：libbpf-rs 的 `PerfBufferBuilder` 高层 API 不暴露
  `sample_regs_user` / `sample_stack_user`（原 Go 项目靠魔改 cilium 分支实现）。
  集成到真机时需补一个裸 `perf_event_open` syscall 包装（约 200 行）来配置这两个
  `perf_event_attr` 字段，否则只能采到事件头而采不到寄存器/栈快照。代码里已留好接入点
  （`module/stack_probe.rs` 的 `run_perf_loop_stack` / `module/syscall_tracepoint.rs`）。

## 测试

平台无关的字节布局 / JSON / CLI 解析单测可在任何主机运行：

```bash
cargo test --lib
```

关键单测：
- `config::sconfig` — `StackFilter`=32B / `SyscallFilter`=36B 字段偏移与字节值
- `config::hook_json` — 解析 `config.json`、`hex2int`、serde 往返
- `event::ievent` — `LibArg`=288B、`UnwindBuf`/`RegsBuf` 小端往返
- `event::context` — 公共头解码、UUID 格式、regs JSON 键序
- `cli::args` — clap 解析、前缀匹配、默认值
- `assets` — 9 个 .so 全部嵌入且为 ELF

## 许可

MIT，与上游一致。
