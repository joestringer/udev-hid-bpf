// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 */

#include "vmlinux.h"
#include "attach.h"
/*
 * Workaround for libbpf < 1.7 where bpf_helpers.h declares
 * bpf_stream_vprintk with a 5-arg _impl-style signature that
 * conflicts with the 4-arg kfunc in kernel >= 7.0 vmlinux.h.
 * Suppress the redeclaration by shadowing it with a macro.
 */
#define bpf_stream_vprintk __hid_bpf_stream_vprintk_unused
#include <bpf/bpf_helpers.h>
#undef bpf_stream_vprintk

/* following are kfuncs exported by HID for HID-BPF */
extern int hid_bpf_attach_prog(unsigned int hid_id, int prog_fd, u32 flags) __ksym;

SEC("syscall")
int attach_prog(struct attach_prog_args *ctx)
{
	ctx->retval = hid_bpf_attach_prog(ctx->hid,
					  ctx->prog_fd,
					  0);
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = 1;
