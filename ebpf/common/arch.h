#ifndef __STACKPLZ_ARCH_H__
#define __STACKPLZ_ARCH_H__

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common/common.h"

// Upstream dev defined PT_REGS_PARM6 here for __TARGET_ARCH_x86/arm64. It had
// no callers in either tree, so it was dropped as dead code -- it was NOT
// replaced by libbpf: the vendored bpf/bpf_tracing.h stops at PT_REGS_PARM5 and
// does not provide PT_REGS_PARM6 for any architecture. Re-add a local
// definition here if a probe ever needs the 6th argument register.
//
// 本工程 eBPF 侧只实现 arm64/arm 寄存器语义：common/task.h 的 compat32 判定只区分
// __TARGET_ARCH_arm 与其余构建，syscall.c/stack.c 的 lr/sp 取自 AArch64 的
// regs[30]/regs[14]/regs[13]。上游曾在此为 __TARGET_ARCH_x86 定义 PT_REGS_PARM6，
// 现已删掉，本工程再无任何 x86_64 寄存器路径：x86_64 构建可编译（CI 会跑），但
// lr/sp 不可信，只是构建目标而非受支持平台（见 README「架构限制」）。
// shortcut: x86_64 仅编译（无寄存器模型），等真正需要 x86_64 目标时补全。

#endif