#ifndef __STACKPLZ_ARCH_H__
#define __STACKPLZ_ARCH_H__

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common/common.h"

// PT_REGS_PARM6 is now provided by libbpf's bpf_tracing.h for all architectures
// No need to redefine it here

#endif