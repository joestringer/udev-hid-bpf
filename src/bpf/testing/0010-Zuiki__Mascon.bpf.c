// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

#define VID_ZUIKI 0x33dd
#define PID_MASCON 0x0001

HID_BPF_CONFIG(
     HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_ZUIKI, PID_MASCON)
);

struct __attribute__((__packed__)) event {
    __u8 type;
    __u16 axis0;
    __u16 axis1;
    __u16 axis2;
};

static inline __u16 transform(__u16 input) {
    // Zero out the X axis that games interpret as "full-left" X axis
    return input & 0xFF00;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(mascon_remove_axis, struct hid_bpf_ctx *hid_ctx)
{
    const int expected_length = sizeof(struct event);
    const int expected_report_id = 0;
    __u8 *data;
    struct event *ev;

    if (hid_ctx->size < expected_length) {
        //bpf_printk("%s: skipping event with length %d", __func__, hid_ctx->size);
        return 0;
    }

    data = hid_bpf_get_data(hid_ctx, 0, expected_length);
    if (!data) {
        //bpf_printk("%s: no hid data", __func__);
        return 0; /* EPERM or the wrong report ID */
    }
    if (data[0] != expected_report_id) {
        //bpf_printk("%s: unexpected report id: %d", __func__, data[0]);
        return 0; /* EPERM or the wrong report ID */
    }

    ev = (struct event *)data;
    ev->axis0 = 0;
    ev->axis1 = transform(ev->axis1);
    ev->axis2 = 0;
    //bpf_printk("input: %02x %04x %04x %04x", ev->type, ev->axis0, ev->axis1, ev->axis2);

    return 0;
}

HID_BPF_OPS(ignore_button) = {
  .hid_device_event = (void *)mascon_remove_axis,
};

char _license[] SEC("license") = "GPL";
