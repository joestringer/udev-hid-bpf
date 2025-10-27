// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>

/*
 * Device ID Note:
 * Vendor ID:  0x5ac - Apple Inc.
 * Product ID: 0x22c - USB_DEVICE_ID_APPLE_ALU_WIRELESS_ANSI (Apple Aluminum Wireless Keyboard)
 *
 * This device masquerades as an Apple keyboard to leverage special handling
 * and automatic driver support in diferent OSes. These VID\PID has my device,
 * maybe yours will have different values
 */
#define VID_MINI_KEYBOARD   0x5ac
#define PID_MINI_KEYBOARD   0x22c
#define RDESC_SIZE  140

/*
// original BLE hid report descriptor
# device 0:0
# 0x05, 0x01,                    // Usage Page (Generic Desktop)        0
# 0x09, 0x02,                    // Usage (Mouse)                       2
# 0xa1, 0x01,                    // Collection (Application)            4
# 0x85, 0x01,                    //  Report ID (1)                      6
# 0x09, 0x01,                    //  Usage (Pointer)                    8
# 0xa1, 0x00,                    //  Collection (Physical)              10
# 0x05, 0x09,                    //   Usage Page (Button)               12
# 0x19, 0x01,                    //   Usage Minimum (1)                 14
# 0x29, 0x03,                    //   Usage Maximum (3)                 16
# 0x15, 0x00,                    //   Logical Minimum (0)               18
# 0x25, 0x01,                    //   Logical Maximum (1)               20
# 0x75, 0x01,                    //   Report Size (1)                   22
# 0x95, 0x08,                    //   Report Count (8)                  24
# 0x81, 0x02,                    //   Input (Data,Var,Abs)              26
# 0x05, 0x01,                    //   Usage Page (Generic Desktop)      28
# 0x09, 0x30,                    //   Usage (X)                         30
# 0x09, 0x31,                    //   Usage (Y)                         32
# 0x09, 0x38,                    //   Usage (Wheel)                     34
# 0x15, 0x81,                    //   Logical Minimum (-127)            36
# 0x25, 0x7f,                    //   Logical Maximum (127)             38
# 0x75, 0x08,                    //   Report Size (8)                   40
# 0x95, 0x03,                    //   Report Count (3)                  42
# 0x81, 0x06,                    //   Input (Data,Var,Rel)              44
# 0xc0,                          //  End Collection                     46
# 0xc0,                          // End Collection                      47
# 0x05, 0x01,                    // Usage Page (Generic Desktop)        48
# 0x09, 0x06,                    // Usage (Keyboard)                    50
# 0xa1, 0x01,                    // Collection (Application)            52
# 0x85, 0x02,                    //  Report ID (2)                      54
# 0x05, 0x07,                    //  Usage Page (Keyboard)              56
# 0x19, 0xe0,                    //  Usage Minimum (224)                58
# 0x29, 0xe7,                    //  Usage Maximum (231)                60
# 0x15, 0x00,                    //  Logical Minimum (0)                62
# 0x25, 0x01,                    //  Logical Maximum (1)                64
# 0x75, 0x01,                    //  Report Size (1)                    66
# 0x95, 0x08,                    //  Report Count (8)                   68
# 0x81, 0x02,                    //  Input (Data,Var,Abs)               70
# 0x95, 0x01,                    //  Report Count (1)                   72
# 0x75, 0x08,                    //  Report Size (8)                    74
# 0x81, 0x01,                    //  Input (Cnst,Arr,Abs)               76
# 0x95, 0x05,                    //  Report Count (5)                   78
# 0x75, 0x01,                    //  Report Size (1)                    80
# 0x05, 0x08,                    //  Usage Page (LEDs)                  82
# 0x19, 0x01,                    //  Usage Minimum (1)                  84
# 0x29, 0x05,                    //  Usage Maximum (5)                  86
# 0x91, 0x02,                    //  Output (Data,Var,Abs)              88
# 0x95, 0x01,                    //  Report Count (1)                   90
# 0x75, 0x03,                    //  Report Size (3)                    92
# 0x91, 0x01,                    //  Output (Cnst,Arr,Abs)              94
# 0x95, 0x06,                    //  Report Count (6)                   96
# 0x75, 0x08,                    //  Report Size (8)                    98
# 0x15, 0x00,                    //  Logical Minimum (0)                100
# 0x25, 0x65,                    //  Logical Maximum (101)              102
# 0x05, 0x07,                    //  Usage Page (Keyboard)              104
# 0x19, 0x00,                    //  Usage Minimum (0)                  106
# 0x29, 0x65,                    //  Usage Maximum (101)                108
# 0x81, 0x00,                    //  Input (Data,Arr,Abs)               110
# 0xc0,                          // End Collection                      112
# 0x05, 0x0c,                    // Usage Page (Consumer Devices)       113
# 0x09, 0x01,                    // Usage (Consumer Control)            115
# 0xa1, 0x01,                    // Collection (Application)            117
# 0x85, 0x03,                    //  Report ID (3)                      119
# 0x95, 0x01,                    //  Report Count (1)                   121
# 0x75, 0x10,                    //  Report Size (16)                   123
# 0x16, 0x00, 0x00,              //  Logical Minimum (0)                125
# 0x26, 0xff, 0x02,              //  Logical Maximum (767)              128
# 0x1a, 0x00, 0x00,              //  Usage Minimum (0)                  131
# 0x2a, 0xff, 0x02,              //  Usage Maximum (767)                134
# 0x81, 0x00,                    //  Input (Data,Arr,Abs)               137
# 0xc0,                          // End Collection                      139
# 
R: 140 05 01 09 02 a1 01 85 01 09 01 a1 00 05 09 19 01 29 03 15 00 25 01 75 01 95 08 81 02 05 01 09 30 09 31 09 38 15 81 25 7f 75 08 95 03 81 06 c0 c0 05 01 09 06 a1 01 85 02 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 95 01 75 08 81 01 95 05 75 01 05 08 19 01 29 05 91 02 95 01 75 03 91 01 95 06 75 08 15 00 25 65 05 07 19 00 29 65 81 00 c0 05 0c 09 01 a1 01 85 03 95 01 75 10 16 00 00 26 ff 02 1a 00 00 2a ff 02 81 00 c0
N: device 0:0
I: 3 0001 0001
*/


HID_BPF_CONFIG(
    HID_DEVICE(BUS_BLUETOOTH, HID_GROUP_ANY, VID_MINI_KEYBOARD, PID_MINI_KEYBOARD)
);


SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(hid_rdesc_fixup_mini_keyboard, struct hid_bpf_ctx *hctx)
{
    __u8 *data = hid_bpf_get_data(hctx, 0, HID_MAX_DESCRIPTOR_SIZE);
    if (!data)
        return 0; /* EPERM check */
    
    if (data[103] == 0x65 && data[109] == 0x65){
        data[103] = 0xff;
        data[109] = 0xff;
    }

    return 0;
}

HID_BPF_OPS(general_minikeyboard) = {
    .hid_rdesc_fixup = (void *)hid_rdesc_fixup_mini_keyboard,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
    ctx->retval = ctx->rdesc_size != RDESC_SIZE;
    if (ctx->retval)
        ctx->retval = -EINVAL;

    return 0;
}

char _license[] SEC("license") = "GPL";
