// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Red Hat
 *
 * Test BPF program for testing:
 * - HID report descriptor injection
 * - extract_bits optimizations
 * - Iterator macros
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_descriptor_helpers.h"
#include <bpf/bpf_tracing.h>

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, 0x1234, 0x5678),
);

/* to be filled by udev-hid-bpf */
struct hid_rdesc_descriptor HID_REPORT_DESCRIPTOR;

/* Test parameters (set by pytest before running test) */
__u32 test_bits_start;
__u32 test_bits_end;

/* Test result storage */
__u32 test_extract_result;

__u32 test_feature_report_count;
__u32 test_input_report_count;
__u32 test_field_count;
__u32 test_collection_count;
__u32 test_max_collections_per_field;

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(test_extract_bits, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, 64);
	struct hid_rdesc_field field;

	if (!data)
		return 0;

	field.bits_start = (__u16)test_bits_start;
	field.bits_end = (__u16)test_bits_end;
	test_extract_result = extract_bits(data, 64, &field);

	return 0;
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	struct hid_rdesc_report *feature;
	struct hid_rdesc_report *input;
	struct hid_rdesc_field *field;
	struct hid_rdesc_collection *col;

	/* Test iterator: count feature reports */
	test_feature_report_count = 0;
	hid_bpf_for_each_feature_report(&HID_REPORT_DESCRIPTOR, feature) {
		test_feature_report_count++;

		/* Test iterator: count fields in feature report */
		hid_bpf_for_each_field(feature, field) {
			test_field_count++;
		}
	}

	/* Test iterator: count input reports */
	test_input_report_count = 0;
	test_field_count = 0;
	test_collection_count = 0;
	test_max_collections_per_field = 0;

	hid_bpf_for_each_input_report(&HID_REPORT_DESCRIPTOR, input) {
		test_input_report_count++;

		/* Test iterator: count fields in input report */
		hid_bpf_for_each_field(input, field) {
			__u32 field_collection_count = 0;
			test_field_count++;

			/* Test iterator: count collections in field */
			hid_bpf_for_each_collection(field, col) {
				(void)col; /* Intentionally unused - we're just counting */
				test_collection_count++;
				field_collection_count++;
			}

			/* Track maximum collections per field */
			if (field_collection_count > test_max_collections_per_field)
				test_max_collections_per_field = field_collection_count;
		}
	}

	ctx->retval = 0;
	return 0;
}

HID_BPF_OPS(test_helpers) = {
	.hid_device_event = (void *)test_extract_bits,
};

char _license[] SEC("license") = "GPL";
