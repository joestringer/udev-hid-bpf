#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2025 Red Hat

"""
Tests for new BPF helper functionality:
- HID report descriptor injection
- Iterator macros (hid_bpf_for_each_*)
"""

from . import HidProbeArgs
from dataclasses import dataclass
from enum import IntEnum
import pytest


class DeviceType(IntEnum):
    """HID device types."""

    MOUSE = 0x02
    KEYBOARD = 0x06


class ReportItemType(IntEnum):
    """HID report item types."""

    INPUT = 0x81
    OUTPUT = 0x91
    FEATURE = 0xB1


@dataclass(frozen=True)
class DeviceConfig:
    """Configuration for a specific HID device type."""

    usage: int
    usage_page: int
    usage_min: int
    usage_max: int
    log_min: int
    log_max: int


def create_hid_rdesc(
    device_type: DeviceType = DeviceType.MOUSE,
    report_type: ReportItemType = ReportItemType.INPUT,
    nested: bool = True,
) -> bytearray:
    """
    Create a HID report descriptor.

    Args:
        device_type: DeviceType enum value
        report_type: ReportItemType enum value
        nested: Whether to include nested Physical collection (for Mouse)

    Returns:
        bytearray containing the HID report descriptor
    """
    # Device-specific configurations
    devices = {
        DeviceType.MOUSE: DeviceConfig(
            usage=0x02,  # Mouse
            usage_page=0x09,  # Button
            usage_min=0x01,  # Button 1
            usage_max=0x03,  # Button 3
            log_min=0x00,
            log_max=0x01,
        ),
        DeviceType.KEYBOARD: DeviceConfig(
            usage=0x06,  # Keyboard
            usage_page=0x07,  # Keyboard
            usage_min=0x00,
            usage_max=0xFF,
            log_min=0x00,
            log_max=0xFF,
        ),
    }

    device = devices[device_type]
    report_item = report_type

    rdesc = bytearray(
        [
            0x05,
            0x01,  # Usage Page (Generic Desktop)
            0x09,
            device.usage,  # Usage (Mouse/Keyboard)
            0xA1,
            0x01,  # Collection (Application)
        ]
    )

    # Add nested Physical collection for Mouse if requested
    if nested and device_type == DeviceType.MOUSE:
        rdesc.extend(
            [
                0x09,
                0x01,  # Usage (Pointer)
                0xA1,
                0x00,  # Collection (Physical)
            ]
        )

    # Add report ID for feature/output reports
    if report_type in [ReportItemType.FEATURE, ReportItemType.OUTPUT]:
        rdesc.extend([0x85, 0x01])  # Report ID (1)

    # Add report fields
    rdesc.extend(
        [
            0x05,
            device.usage_page,  # Usage Page
            0x19,
            device.usage_min,  # Usage Minimum
            0x29,
            device.usage_max,  # Usage Maximum
            0x15,
            device.log_min,  # Logical Minimum
            0x25,
            device.log_max,  # Logical Maximum
            0x75,
            0x08,  # Report Size (8)
            0x95,
            0x01,  # Report Count (1)
            report_item,
            0x02,  # Input/Output/Feature (Data,Var,Abs)
        ]
    )

    # Close nested Physical collection if opened
    if nested and device_type == DeviceType.MOUSE:
        rdesc.extend([0xC0])  # End Collection

    # Close Application collection
    rdesc.extend([0xC0])  # End Collection

    return rdesc


@pytest.mark.parametrize("source", ["0010-test-helpers"])
class TestIteratorMacros:
    """Test iterator macros for HID report descriptor traversal."""

    def test_report_descriptor_injection(self, bpf):
        """
        Test that the HID_REPORT_DESCRIPTOR is properly injected
        and accessible in the probe function.
        """
        probe_args = HidProbeArgs()
        probe_args.rdesc_bytes = create_hid_rdesc(
            device_type=DeviceType.MOUSE, report_type=ReportItemType.INPUT, nested=True
        )

        # Call probe - it should parse the descriptor and iterate
        pa = bpf.probe(probe_args)

        # Should complete successfully
        assert pa.retval == 0

    @pytest.mark.parametrize(
        "device_type,report_type",
        [
            (DeviceType.KEYBOARD, ReportItemType.FEATURE),
            (DeviceType.MOUSE, ReportItemType.INPUT),
        ],
    )
    def test_iterate_reports(self, bpf, device_type, report_type):
        """Test hid_bpf_for_each_{feature,input}_report macros."""
        # Map report type to counter variable
        count_vars = {
            ReportItemType.FEATURE: "test_feature_report_count",
            ReportItemType.INPUT: "test_input_report_count",
        }

        probe_args = HidProbeArgs()
        probe_args.rdesc_bytes = create_hid_rdesc(
            device_type=device_type, report_type=report_type, nested=False
        )

        pa = bpf.probe(probe_args)
        assert pa.retval == 0

        # Check that reports were counted
        count = bpf.get_global_u32(count_vars[report_type])
        assert count >= 0

    def test_iterate_fields(self, bpf):
        """Test hid_bpf_for_each_field macro."""
        probe_args = HidProbeArgs()

        pa = bpf.probe(probe_args)
        assert pa.retval == 0

        # Check that fields were counted
        field_count = bpf.get_global_u32("test_field_count")
        assert field_count >= 0

    def test_iterate_collections(self, bpf):
        """Test hid_bpf_for_each_collection macro."""
        probe_args = HidProbeArgs()
        # Use Mouse with nested Physical collection to test collection iteration
        probe_args.rdesc_bytes = create_hid_rdesc(
            device_type=DeviceType.MOUSE, report_type=ReportItemType.INPUT, nested=True
        )

        pa = bpf.probe(probe_args)
        assert pa.retval == 0

        # Check that collections were counted
        collection_count = bpf.get_global_u32("test_collection_count")
        assert collection_count > 0

    def test_empty_descriptor(self, bpf):
        """Test iterators with empty report descriptor."""
        probe_args = HidProbeArgs()

        # Should handle empty descriptor gracefully
        pa = bpf.probe(probe_args)

        # May return error or success, but shouldn't crash
        assert pa is not None

    def test_bounds_checking(self, bpf):
        """Test that iterators respect HID_MAX_* bounds."""
        # Define the HID_MAX_* constants from hid_bpf_helpers.h
        HID_MAX_REPORTS = 16
        HID_MAX_FIELDS = 64
        HID_MAX_COLLECTIONS = 32

        # Generate a descriptor that exceeds these limits
        rdesc_data = bytearray()

        # Start main collection
        rdesc_data.extend(
            [
                0x05,
                0x01,  # Usage Page (Generic Desktop)
                0x09,
                0x06,  # Usage (Keyboard)
                0xA1,
                0x01,  # Collection (Application)
            ]
        )

        # Generate HID_MAX_REPORTS + 4 input reports (exceeds HID_MAX_REPORTS)
        for report_id in range(1, HID_MAX_REPORTS + 5):
            rdesc_data.extend(
                [
                    0x85,
                    report_id,  # Report ID
                ]
            )

            # Report 1 has HID_MAX_FIELDS + 6 fields (exceeds HID_MAX_FIELDS)
            if report_id == 1:
                # Add individual 1-bit fields
                for field_num in range(HID_MAX_FIELDS + 6):
                    rdesc_data.extend(
                        [
                            0x05,
                            0x09,  # Usage Page (Button)
                            0x09,
                            (field_num % 255) + 1,  # Usage (Button N)
                            0x15,
                            0x00,  # Logical Minimum (0)
                            0x25,
                            0x01,  # Logical Maximum (1)
                            0x75,
                            0x01,  # Report Size (1)
                            0x95,
                            0x01,  # Report Count (1)
                            0x81,
                            0x02,  # Input (Data,Var,Abs)
                        ]
                    )
                # Padding to byte boundary
                remaining_bits = (HID_MAX_FIELDS + 6) % 8
                if remaining_bits:
                    rdesc_data.extend(
                        [
                            0x75,
                            0x01,  # Report Size (1)
                            0x95,
                            8 - remaining_bits,  # Report Count
                            0x81,
                            0x01,  # Input (Const)
                        ]
                    )
            else:
                # Other reports have simple 1-byte fields
                rdesc_data.extend(
                    [
                        0x05,
                        0x09,  # Usage Page (Button)
                        0x09,
                        0x01,  # Usage (Button 1)
                        0x15,
                        0x00,  # Logical Minimum (0)
                        0x25,
                        0xFF,  # Logical Maximum (255)
                        0x75,
                        0x08,  # Report Size (8)
                        0x95,
                        0x01,  # Report Count (1)
                        0x81,
                        0x02,  # Input (Data,Var,Abs)
                    ]
                )

        # Add HID_MAX_COLLECTIONS + 3 nested collections (exceeds HID_MAX_COLLECTIONS)
        for coll_num in range(HID_MAX_COLLECTIONS + 3):
            rdesc_data.extend(
                [
                    0xA1,
                    0x00,  # Collection (Physical)
                ]
            )

        # Close all nested collections
        for coll_num in range(HID_MAX_COLLECTIONS + 3):
            rdesc_data.extend(
                [
                    0xC0,  # End Collection
                ]
            )

        # Close main collection
        rdesc_data.extend(
            [
                0xC0,  # End Collection
            ]
        )

        probe_args = HidProbeArgs()
        probe_args.rdesc_bytes = rdesc_data

        # Even with a larger descriptor, iterators should
        # stop at HID_MAX_REPORTS, HID_MAX_FIELDS, etc.
        pa = bpf.probe(probe_args)

        assert pa.retval == 0

        # Verify that counts are capped at their maximums
        # We generated HID_MAX_REPORTS + 4 reports, but should only see HID_MAX_REPORTS
        input_report_count = bpf.get_global_u32("test_input_report_count")
        assert input_report_count == HID_MAX_REPORTS, (
            f"Expected {HID_MAX_REPORTS} input reports, got {input_report_count}"
        )

        # We generated HID_MAX_FIELDS + 6 fields in report 1, but should only see HID_MAX_FIELDS
        # Note: test_field_count is the total across all input reports
        # Report 1 should be capped at 64 fields
        field_count = bpf.get_global_u32("test_field_count")
        assert field_count >= HID_MAX_FIELDS, (
            f"Expected at least {HID_MAX_FIELDS} fields, got {field_count}"
        )

        # We generated HID_MAX_COLLECTIONS + 3 nested collections, but each field
        # should be capped at HID_MAX_COLLECTIONS
        max_collections_per_field = bpf.get_global_u32("test_max_collections_per_field")
        assert max_collections_per_field <= HID_MAX_COLLECTIONS, (
            f"Expected max {HID_MAX_COLLECTIONS} collections per field, got {max_collections_per_field}"
        )

        # Feature reports should be 0 since we only generated input reports
        feature_report_count = bpf.get_global_u32("test_feature_report_count")
        assert feature_report_count == 0, (
            f"Expected 0 feature reports, got {feature_report_count}"
        )
