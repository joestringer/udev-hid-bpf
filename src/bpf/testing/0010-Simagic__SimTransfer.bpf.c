// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_SIMAGIC 0x0483
#define PID_SIMTRANSFER 0x051F

HID_BPF_CONFIG(
     HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_SIMAGIC, PID_SIMTRANSFER)
);

struct __attribute__((__packed__)) event {
    __u8 type;
    __u16 axis1;
    __u16 axis2;
    __u16 axis3;
    __u32 pad1;
    __u16 pad2;
    __u8  pad3;
};

static inline __u16 transform(__u16 input) {
    // Positive axis only
    return input >> 1 | 0x800;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(simagic_single_axis, struct hid_bpf_ctx *hid_ctx)
{
    const int expected_length = sizeof(struct event);
    const int expected_report_id = 1;
    __u8 *data;
    struct event *ev;

    if (hid_ctx->size < expected_length) {
        return 0;
    }

    data = hid_bpf_get_data(hid_ctx, 0, expected_length);
    if (!data) {
        return 0; /* EPERM or the wrong report ID */
    }
    if (data[0] != expected_report_id) {
        return 0; /* EPERM or the wrong report ID */
    }

    ev = (struct event *)data;
    ev->axis1 = transform(ev->axis1);
    ev->axis2 = transform(ev->axis2);
    ev->axis3 = transform(ev->axis3);
    //bpf_printk("input: %02x %04x %04x %04x", ev->type, ev->axis1, ev->axis2, ev->axis3);

    return 0;
}

HID_BPF_OPS(ignore_button) = {
  .hid_device_event = (void *)simagic_single_axis,
};

char _license[] SEC("license") = "GPL";
