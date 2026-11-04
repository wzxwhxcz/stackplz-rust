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

#endif