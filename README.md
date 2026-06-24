# stackplz-rs

Rust 重构版 [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz) —— 一款基于 eBPF 的 Android 堆栈追踪工具。

同步自上游 **dev 分支**（`d4bf8cd`），底层用 Rust 重写，eBPF C 源码原样复用。

## 与原项目的对照

| 维度 | 原 Go 项目 | 本 Rust 版 |
|------|-----------|-----------|
| CLI 框架 | `spf13/cobra` | `clap` v4 derive（`infer_long_args` 复刻 cobra 前缀匹配） |
| eBPF 加载 | 魔改 `cilium/ebpf` + `ehids/ebpfmanager` | `libbpf-rs` 0.23 |
| 栈回溯 | cgo `dlopen` 预编译 `libstackplz.so` | `libloading` dlopen 同一批 `preload_libs/*.so` |
| 资产嵌入 | `go-bindata` | `include_bytes!` |
| 配置 | `encoding/json` | `serde` / `serde_json` |
| ELF 符号解析 | `ebpfmanager` 内部 | `object` crate |
| eBPF C 源 | dev 分支 | **原样复制**（19 个文件，零改动） |

## 目录结构

```
stackplz-rs/
├── Cargo.toml
├── build.rs                # clang 编译 ebpf/*.c -> ebpf/bpf/*.o（3 个对象）
├── build_env.sh            # 拉取 libbpf 源码 + bpftool + BTF
├── ebpf/                   # eBPF C 源（dev 分支原样复制）
│   ├── stack.c             # uprobe handler（probe_stack_0..5）
│   ├── syscall.c           # raw_tracepoint/sys_enter + sys_exit
│   ├── perf_mmap.c         # perf_mmap 模块
│   ├── types.h             # dev 契约结构体（op_config_t, point_args_t, ...）
│   ├── maps.h              # BPF map 定义（op_list, uprobe_point_args, events, ...）
│   ├── utils.h             # read_args() op VM 解释器
│   └── common/             # buffer.h, consts.h, filtering.h, ...
├── assets/preload_libs/    # 预编译 .so（9 个，含 libstackplz.so + libunwindstack.so）
└── src/
    ├── main.rs             # 入口
    ├── lib.rs              # 模块声明
    ├── assets.rs           # include_bytes! 嵌入 .so
    ├── logger.rs           # 日志（stdout + file）
    ├── cli/                # clap CLI + 子命令 handler
    │   ├── args.rs         # GlobalArgs + StackArgs + SyscallArgs
    │   ├── root.rs         # persistent_pre_run（资产释放、目标解析）
    │   ├── stack_cmd.rs    # stack 子命令（-w 解析 + 多模块分发）
    │   └── syscall_cmd.rs  # syscall 子命令
    ├── config/             # 配置层
    │   ├── global.rs       # GlobalConfig（全部 dev 全局 flag）
    │   ├── stack.rs        # StackConfig + ProbeConfig
    │   ├── sconfig.rs      # SConfig + StackFilter + SyscallFilter
    │   ├── point_arg.rs    # PointArg + UprobeArgs + GetOpList()
    │   ├── point_parser.rs # -w 字符串解析器（ParseArgType + Parse_HookPoint）
    │   └── hook_json.rs    # JSON 配置（master-era schema）
    ├── contract/           # dev eBPF 契约层（平台无关，带 141 个单测）
    │   ├── types.rs        # #[repr(C)] 结构体（56 个，字节布局断言）
    │   ├── enums.rs        # EventId, OpCode(34), ArgType(40), ArgFilterType, ...
    │   ├── consts.rs       # 常量 + common_list 偏移段
    │   ├── args.rs         # ArgsCursor（TLV 读取器）
    │   └── decode.rs       # decode_perf_record()（56B 头 + eventid 分派）
    ├── argtype/            # 参数类型系统（Phase 1）
    │   ├── op.rs           # OpManager + 34 个 op 单例 + dedup
    │   ├── consts.rs       # 57 个类型索引常量 + 结构体大小/偏移
    │   ├── registry.rs     # ArgType 注册表（Register/GetArgType/with_type）
    │   ├── base_types.rs   # init_base_types（ptr/int/buffer/string/struct/array）
    │   └── complex_types.rs# pre_register（25+ 扩展类型 + 动态构造器）
    ├── ebpf/               # eBPF 胶水
    │   ├── bpf_common.rs   # libbpf-rs 加载 + map 写入辅助
    │   └── capability.rs   # /proc/config.gz 解析
    ├── event/              # 事件解码（master-era，待迁移到 dev 契约）
    │   ├── context.rs      # ContextEvent 解码
    │   ├── ievent.rs       # LibArg + UnwindBuf + RegsBuf
    │   ├── hook.rs         # HookDataEvent 渲染
    │   ├── syscall_event.rs# SyscallDataEvent
    │   └── unwind_ffi.rs   # dlopen libstackplz.so get_stack
    ├── module/             # 运行时模块
    │   ├── stack_probe.rs  # uprobe 运行时（load + map + attach + perf 轮询）
    │   └── syscall_tracepoint.rs # syscall 运行时（stub，待实现）
    └── util/               # 工具
        ├── fs.rs           # find_lib + read_maps_by_pid
        ├── reg.rs          # parse_reg + MapSegment
        └── hexdump.rs      # hex dump
```

## 构建

通过 GitHub Actions 自动构建（`.github/workflows/build.yml`）：
- **test job**：`cargo test --lib` + `cargo test --test contracts` + clippy + fmt（141 个测试）
- **android job**：clang 编 eBPF .o → bpftool gen BTF → NDK 交叉编译 arm64 → 上传二进制

手动构建：
```bash
./build_env.sh                    # 拉取 libbpf + bpftool + BTF
cargo build --release --features embedded_bpf --target aarch64-linux-android
```

## 使用

```bash
# 释放 preload_libs
./stackplz stack --prepare

# -w hook uprobe（dev 核心功能）
./stackplz --uid 10245 -l libc.so -w "write[int,buf:128,int]" stack --stack --regs
./stackplz --name com.x --library libnative-lib.so -w "0x4B8A74[str:x22,str:x8]" stack

# 符号 hook（master-era 兼容）
./stackplz --uid 10245 stack --symbol open --stack --regs

# JSON 配置
./stackplz --name com.x stack --config config.json
```

### -w 语法

```
symbol[arg1,arg2,...]          基本形式
write[int,buf:128,int]         多参数
strstr+0x0[str,str]            符号 + 偏移
0x5B950[*int:x20]              偏移 + 指针解引用 + 寄存器读取
write[int]0x40                 exit point 克隆
open[str]s                     绑定到 syscall
```

支持的参数类型：`int` `uint` `int8-64` `uint8-64` `str` `std` `str16` `il2cpp_string` `ptr` `buf` `buf:N` `buf:reg` `int_arr:N` `uint_arr:N` `*int`（指针） `intx`（hex） `timespec` `iovec` `stat` 等。

## 移植进度

| 模块 | 完成度 | 说明 |
|------|--------|------|
| eBPF C 源码 | ✅ 100% | 19 个文件原样复制 |
| 契约层 | ✅ ~70% | dev 结构/枚举/常量/TLV/解码，141 个单测 |
| op 管理器 (1a) | ✅ ~90% | 34 个 op 单例 + dedup + 构造器 |
| argtype 注册表 (1b) | ✅ ~45% | 类型注册完整，值解析/渲染待移植 |
| -w 解析器 (2) | ✅ ~80% | 全语法支持（14 个测试） |
| uprobe 运行时 (3) | ✅ ~55% | load + map + attach + perf 轮询 + 事件渲染 |
| BPF map 写入 (4) | ✅ ~80% | op_list/uprobe_point_args/base_config/common_filter/common_list |
| dev CLI flags | ✅ ~60% | 25+ flag 已加，缺 -f/-s/-c/--dump/--parse/--brk* 等 |
| syscall 运行时 | ❌ 5% | stub，返回 "not implemented" |
| 参数值渲染 | ❌ 0% | config_struct.go (884行) 未移植 |
| -f 过滤系统 | ❌ 10% | 只有 wire struct |
| perf_mmap 模块 | ❌ 0% | |
| brk 硬件断点 | ❌ 0% | |
| event_processor | ❌ 0% | |
| --rpc / --parse | ❌ 0% | |

**总体功能完成度：约 35%**

## 测试

```bash
cargo test --lib          # 141 个单测
cargo test --test contracts  # 33 个集成测试
```

## 许可

MIT，与上游一致。
