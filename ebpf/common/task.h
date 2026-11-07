#ifndef __STACKPLZ_TASK_H__
#define __STACKPLZ_TASK_H__

// `bool` / `true` / `false` 由 vmlinux_510.h 自带（与内核一致），
// 这里不能 include <stdbool.h>：它的 `#define bool _Bool` 会把 vmlinux 里的
// `enum { false = 0, true = 1 }` 和 `typedef _Bool bool` 一起打坏。
#include "vmlinux_510.h"

#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "common/common.h"
#include "common/consts.h"

static __always_inline u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;
    pid = READ_KERN(task->thread_pid);
    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}

static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = READ_KERN(task->group_leader);
    return get_task_pid_vnr(group_leader);
}

// 当前任务自身是否运行在 AArch32(compat / 32 位) ABI 下。
// 目的仅有一个：决定 lr/sp 从哪组寄存器读（regs[14]/regs[13] 还是 regs[30]/sp）。
//   - arm 构建：目标恒为 32 位，不读 flags，直接 true；
//   - arm64 构建：读 thread_info.flags 的 _TIF_32BIT(1<<22，arm64 专属位)，即目标
//     进程自己的 ABI，而不是 stackplz 宿主二进制的架构；
//   - x86_64 构建：本工程 eBPF 侧没有 x86_64 寄存器模型 —— syscall.c/stack.c 读的是
//     AArch64 的 regs[30]/regs[14]/regs[13]，而 x86_64 上 bit 22 的含义完全不同。
//     所以此构建下 compat32 的答案无意义、lr/sp 不可信；x86_64 只是「能编译过」的
//     构建/CI 目标，不是受支持的目标平台（见 README「架构限制」）。
// shortcut: eBPF 侧只实现 arm64/arm 寄存器语义（x86_64 仅编译），等真正需要 x86_64
// 目标时补 __TARGET_ARCH_x86 分支 + syscall.c/stack.c 的 ip/sp 读取，并同步更新
// README 与 tests/ebpf_sources.rs 的声明测试。
// 注意：本函数是「寄存器来源选择器」，不是过滤器 —— 不要在这里或调用处基于它
// 提前 return / 丢弃事件，否则会重新引入「架构门控导致零事件」的缺陷（已在上一轮删除）。
static __always_inline bool is_current_task_compat32(void)
{
#if defined(__TARGET_ARCH_arm)
    return true;
#else
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (task == NULL) {
        return false;
    }
    return (BPF_CORE_READ(task, thread_info.flags) & _TIF_32BIT) != 0;
#endif
}

#endif
