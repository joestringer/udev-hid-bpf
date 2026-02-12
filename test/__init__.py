#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 Red Hat

from ctypes import (
    c_int,
)
from typing import Optional, Tuple, Type, Self
from dataclasses import dataclass
from pathlib import Path
from enum import IntEnum

import base64
import binascii
import logging
import ctypes
import os
import json
import pytest
import random
import collections
import dataclasses
import errno
import subprocess

from .btf import Btf, Map

logger = logging.getLogger(__name__)
random.seed()


# to be automatically field by BTF thanks to libbpf
class HidDevice(ctypes.Structure):
    cname = "hid_device"


# see struct hid_probe_args
class HidProbeArgs(ctypes.Structure):
    cname = "hid_bpf_probe_args"

    @property
    def rdesc_bytes(self) -> bytes:
        """
        Get the report descriptor bytes.

        Returns:
            The report descriptor as bytes (up to rdesc_size)
        """
        return bytes(self.rdesc[: self.rdesc_size])

    @rdesc_bytes.setter
    def rdesc_bytes(self, rdesc_data: bytes | bytearray):
        """
        Set the report descriptor data and size.

        Args:
            rdesc_data: The report descriptor bytes to set

        Example:
            probe_args = HidProbeArgs()
            probe_args.rdesc_bytes = bytearray([0x05, 0x01, 0x09, 0x02, ...])
        """
        for i, byte in enumerate(rdesc_data[: len(self.rdesc)]):
            self.rdesc[i] = byte
        self.rdesc_size = min(len(rdesc_data), len(self.rdesc))


# see struct hid_bpf_ctx
class HidBpfCtx(ctypes.Structure):
    cname = "hid_bpf_ctx"


class BpfTimer(ctypes.Structure):
    cname = "bpf_timer"


class BpfWq(ctypes.Structure):
    cname = "bpf_wq"


class HidRdescDescriptor(ctypes.Structure):
    cname = "hid_rdesc_descriptor"


class TestAsyncCb(ctypes.Structure):
    cname = "test_async_cb"
    _fields_overrides_ = {
        "cb": ctypes.c_void_p,  # just too complex to handle function pointers
    }


@dataclass
class OutputReport:
    time: int
    data: Tuple[bytes]


class ReportType(IntEnum):
    INPUT = 0
    OUTPUT = 1
    FEATURE = 2


class RequestType(IntEnum):
    GET_REPORT = 0x01
    GET_IDLE = 0x02
    GET_PROTOCOL = 0x03
    SET_REPORT = 0x09
    SET_IDLE = 0x0A
    SET_PROTOCOL = 0x0B


@dataclass
class HidRawRequest:
    time: int
    req_data: Tuple[bytes]
    out_data: Tuple[bytes]
    report_type: ReportType
    request_type: RequestType


@dataclass
class InputReport:
    time: int
    data: Tuple[bytes]
    report_type: ReportType


@dataclass
class PrivateBpfNumIterator:
    start: int
    end: int
    current_value: Optional[int] = dataclasses.field(default=None)

    def __iter__(self):
        return self

    def __next__(self):
        if self.current_value is None:
            self.current_value = self.start
        else:
            self.current_value += 1

        if self.current_value >= self.end:
            raise StopIteration

        return ctypes.c_int(self.current_value)


@dataclass
class PrivateTestData:
    bpf: "Bpf"
    current_ctx: HidBpfCtx = dataclasses.field(default_factory=HidBpfCtx)
    id: int = dataclasses.field(default_factory=lambda: random.randint(0, 0xFFFF))
    vendor: int = 0
    product: int = 0
    output_reports: list[OutputReport] = dataclasses.field(default_factory=list)
    hw_requests: list[HidRawRequest] = dataclasses.field(default_factory=list)
    input_reports: list[InputReport] = dataclasses.field(default_factory=list)
    maps_data: dict[int, dict[int, ...]] = dataclasses.field(default_factory=dict)
    queue_data: dict[int, collections.deque] = dataclasses.field(default_factory=dict)
    asyncs: dict[int, TestAsyncCb] = dataclasses.field(default_factory=dict)
    iterators: dict[int, PrivateBpfNumIterator] = dataclasses.field(
        default_factory=dict
    )


# see struct test_callbacks
class Callbacks(ctypes.Structure):
    cname = "test_callbacks"
    _fields_overrides_ = {
        "private_data": ctypes.py_object,
    }

    def __init__(self, private: PrivateTestData):
        hid = HidDevice(id=private.id)
        hid.vendor = private.vendor
        hid.product = private.product
        private.current_ctx.hid = ctypes.pointer(hid)

        super().__init__(private_data=ctypes.py_object(private))
        fun_type = ctypes.CFUNCTYPE(None)
        for field, argtype in self._fields_:
            if isinstance(argtype, type(fun_type)):
                fun = getattr(Callbacks, f"_{field}")
                setattr(self, field, argtype(fun))

    def _hid_bpf_allocate_context(callbacks_p, hid: int):
        callbacks = callbacks_p.contents

        pdata = callbacks.private_data
        assert pdata.id == hid

        callbacks.ctx = ctypes.pointer(pdata.current_ctx)

        return 0

    def _hid_bpf_release_context(callbacks_p, ctx):
        callbacks = callbacks_p.contents

        callbacks.ctx = None

    @classmethod
    def validate_ctx(cls, callbacks_p, ctx_p):
        callbacks = callbacks_p.contents
        hid = ctx_p.contents.hid.contents
        return hid.id == callbacks.private_data.id

    def _hid_bpf_hw_output_report(callbacks_p, ctx_p, data_p, size):
        if not Callbacks.validate_ctx(callbacks_p, ctx_p):
            return -errno.EINVAL
        DataArray = ctypes.c_uint8 * size
        c_data = DataArray()
        p2 = ctypes.byref(c_data)
        ctypes.memmove(p2, data_p, size)
        data = bytes(c_data)

        callbacks = callbacks_p.contents
        callbacks.private_data.output_reports.append(OutputReport(callbacks.time, data))
        return size

    def _hid_bpf_hw_request(callbacks_p, ctx_p, data_p, size, _type, reqtype):
        if not Callbacks.validate_ctx(callbacks_p, ctx_p):
            return -errno.EINVAL
        DataArray = ctypes.c_uint8 * size
        c_data = DataArray()
        p2 = ctypes.byref(c_data)
        ctypes.memmove(p2, data_p, size)
        req_data = bytes(c_data)
        out_data = bytes(c_data)

        callbacks = callbacks_p.contents
        callbacks.private_data.hw_requests.append(
            HidRawRequest(
                callbacks.time,
                req_data,
                out_data,
                ReportType(_type),
                RequestType(reqtype),
            )
        )
        return size

    def _bpf_map_lookup_elem(callbacks_p, map_p, key_p):
        callbacks = callbacks_p.contents

        pdata = callbacks.private_data

        if map_p not in pdata.bpf.maps:
            return -errno.ENOENT

        map = pdata.bpf.maps[map_p]

        # ensure our type is known
        pdata.bpf.btf.build_struct(map.ctype)

        # allocate / get memory
        map_data_dict = pdata.maps_data.setdefault(map_p, {})
        key = ctypes.c_int.from_address(key_p).value
        data = map_data_dict.setdefault(key, map.ctype())

        # store the returned value in callbacks
        callbacks.helpers_retval = ctypes.cast(ctypes.byref(data), ctypes.c_void_p)

        return 0

    def _bpf_map_pop_elem(callbacks_p, map_p, data_p):
        callbacks = callbacks_p.contents
        pdata = callbacks.private_data

        if map_p not in pdata.bpf.maps:
            return -errno.ENOENT

        queue = pdata.queue_data.get(map_p)
        if not queue:
            return -errno.ENOENT

        map = pdata.bpf.maps[map_p]
        value = queue.popleft()
        ctypes.memmove(data_p, ctypes.byref(value), ctypes.sizeof(map.ctype))

        return 0

    def _bpf_map_push_elem(callbacks_p, map_p, data_p, flags):
        callbacks = callbacks_p.contents
        pdata = callbacks.private_data

        if map_p not in pdata.bpf.maps:
            return -errno.ENOENT

        map = pdata.bpf.maps[map_p]
        queue = pdata.queue_data.setdefault(map_p, collections.deque())

        value = map.ctype()
        ctypes.memmove(ctypes.byref(value), data_p, ctypes.sizeof(value))
        queue.append(value)

        return 0

    @classmethod
    def _async_init(cls, callbacks_p, async_p, map_p, clock, async_type):
        callbacks = callbacks_p.contents

        pdata = callbacks.private_data

        if map_p not in pdata.bpf.maps:
            return -errno.ENOENT

        map = pdata.bpf.maps[map_p]
        map_data_dict = pdata.maps_data[map_p]

        async_field = [
            name for name, value in map.ctype._fields_ if value == async_type
        ]

        # this ensures the provided map_p is correct
        assert len(async_field) == 1

        async_field = async_field.pop()

        for key, value in map_data_dict.items():
            t = ctypes.byref(getattr(value, async_field))
            t_p = ctypes.cast(t, ctypes.c_void_p).value
            if async_p == t_p:
                pdata.asyncs[async_p] = TestAsyncCb(
                    map_p,
                    key,
                    ctypes.cast(ctypes.byref(value), ctypes.c_void_p),
                    None,
                )
                return 0

        return -errno.EINVAL

    def _async_set_callback(callbacks_p, async_p, cb):
        callbacks = callbacks_p.contents

        pdata = callbacks.private_data

        if async_p not in pdata.asyncs:
            return -errno.EINVAL

        _async = pdata.asyncs[async_p]
        _async.cb = ctypes.c_void_p(cb)

        return 0

    def _async_start(callbacks_p, async_p, delay, flags):
        callbacks = callbacks_p.contents

        pdata = callbacks.private_data

        if async_p not in pdata.asyncs:
            return -errno.EINVAL

        _async = pdata.asyncs[async_p]

        assert _async.cb is not None

        # store the returned value in callbacks
        callbacks.helpers_retval = ctypes.cast(ctypes.byref(_async), ctypes.c_void_p)

        return 0

    def _bpf_timer_init(callbacks_p, timer_p, map_p, clock):
        return Callbacks._async_init(callbacks_p, timer_p, map_p, clock, BpfTimer)

    def _bpf_wq_init(callbacks_p, wq_p, map_p, clock):
        return Callbacks._async_init(callbacks_p, wq_p, map_p, clock, BpfWq)

    def _bpf_iter_num_new(callbacks_p, iter_p, start, end):
        """
        Initialize a number iterator.
        iter_p points to a bpf_iter_num structure.
        Returns 0 on success.
        """
        callbacks = callbacks_p.contents
        pdata = callbacks.private_data

        pdata.iterators[iter_p] = PrivateBpfNumIterator(start, end)
        return 0

    def _bpf_iter_num_next(callbacks_p, iter_p):
        """
        Get next value from number iterator.
        Returns pointer to current value, or NULL if done.
        """
        callbacks = callbacks_p.contents
        pdata = callbacks.private_data

        if iter_p not in pdata.iterators:
            return None

        iter_state = pdata.iterators[iter_p]

        # Get next value from generator
        current = next(iter_state, None)
        if current is None:
            return None

        callbacks.helpers_retval = ctypes.cast(
            ctypes.byref(current), ctypes.c_void_p
        ).value
        return callbacks.helpers_retval

    def _bpf_iter_num_destroy(callbacks_p, iter_p):
        """
        Clean up number iterator.
        Returns 0 on success.
        """
        callbacks = callbacks_p.contents
        pdata = callbacks.private_data

        if iter_p in pdata.iterators:
            del pdata.iterators[iter_p]

        return 0

    def _hid_bpf_input_report(callbacks_p, ctx_p, _type, data_p, size):
        if not Callbacks.validate_ctx(callbacks_p, ctx_p):
            return -errno.EINVAL
        DataArray = ctypes.c_uint8 * size
        c_data = DataArray()
        p2 = ctypes.byref(c_data)
        ctypes.memmove(p2, data_p, size)
        data = bytes(c_data)

        callbacks = callbacks_p.contents
        callbacks.private_data.input_reports.append(
            InputReport(callbacks.time, data, ReportType(_type))
        )
        return 0


@dataclass
class Api:
    """
    Wrapper to make automatically loading functions from a .so file simpler.
    """

    name: str
    args: Tuple[Type[ctypes._SimpleCData | ctypes._Pointer], ...]
    return_type: Optional[Type[ctypes._SimpleCData | ctypes._Pointer]]
    optional: bool

    @property
    def basename(self) -> str:
        return f"_{self.name}"


class Bpf:
    # Cached .so files
    _libs: dict[str, "Bpf"] = {}

    _api_prototypes: list[Api] = [
        Api(
            name="probe",
            args=(ctypes.POINTER(HidProbeArgs),),
            return_type=c_int,
            optional=True,
        ),
        Api(
            name="set_callbacks",
            args=(ctypes.POINTER(Callbacks),),
            return_type=None,
            optional=False,
        ),
    ]

    def __init__(self, lib, btf: Btf, maps: dict[int, Map]):
        self.lib = lib
        self._callbacks = None
        self.maps = maps
        self.btf = btf

    def get_global_u32(self, name: str) -> int:
        """
        Get a global u32 variable from the loaded BPF program.

        Example:
            value = bpf.get_global_u32("test_extract_8bit_result")
        """
        try:
            var = ctypes.c_uint32.in_dll(self.lib, name)
            return var.value
        except (ValueError, AttributeError) as e:
            raise KeyError(f"Global variable '{name}' not found in BPF program") from e

    def set_global_u32(self, name: str, value: int):
        """
        Set a global u32 variable in the loaded BPF program.

        Example:
            bpf.set_global_u32("test_variable", 42)
        """
        try:
            var = ctypes.c_uint32.in_dll(self.lib, name)
            var.value = value
        except (ValueError, AttributeError) as e:
            raise KeyError(f"Global variable '{name}' not found in BPF program") from e

    def clear_report_descriptor(self) -> bool:
        """
        Clear the HID_REPORT_DESCRIPTOR global variable by memsetting it to 0.

        Returns True if clearing was performed, False if HID_REPORT_DESCRIPTOR doesn't exist.
        """
        # Check if HID_REPORT_DESCRIPTOR exists in the loaded library
        try:
            var_struct = HidRdescDescriptor.in_dll(self.lib, "HID_REPORT_DESCRIPTOR")
        except (ValueError, AttributeError):
            return False

        try:
            struct_size = ctypes.sizeof(HidRdescDescriptor)

            ctypes.memset(ctypes.addressof(var_struct), 0, struct_size)

            logger.warning(f"Cleared {struct_size} bytes of HID_REPORT_DESCRIPTOR")
            return True

        except Exception as e:
            logger.error(f"Failed to clear HID_REPORT_DESCRIPTOR: {e}")
            return False

    def inject_report_descriptor(self, rdesc_bytes: bytes) -> bool:
        """
        Inject parsed HID report descriptor into HID_REPORT_DESCRIPTOR global variable.

        This method:
        1. Checks if HID_REPORT_DESCRIPTOR exists in the loaded BPF program
        2. If it exists, uses hid-rdesc-to-c-struct to convert rdesc_bytes to C-struct
        3. Injects the C-struct data into the HID_REPORT_DESCRIPTOR global variable

        Returns True if injection was performed, False if HID_REPORT_DESCRIPTOR doesn't exist.
        """
        try:
            var_struct = HidRdescDescriptor.in_dll(self.lib, "HID_REPORT_DESCRIPTOR")
        except (ValueError, AttributeError):
            return False

        # Convert rdesc_bytes to C-struct using the tool
        try:
            result = subprocess.run(
                ["hid-rdesc-to-c-struct"],  # base64 is the default format
                input=rdesc_bytes,
                capture_output=True,
                check=True,
            )
            base64_output = result.stdout.decode("utf-8").strip()

            c_struct_bytes = base64.b64decode(base64_output)

            # Get the actual size of the HID_REPORT_DESCRIPTOR struct.
            # We already checked that it was matching the BTF so we know
            # it is the actual binary size.
            struct_size = ctypes.sizeof(HidRdescDescriptor)

            if len(c_struct_bytes) > struct_size:
                logger.error(
                    f"Parsed descriptor size ({len(c_struct_bytes)} bytes) exceeds "
                    f"HID_REPORT_DESCRIPTOR size ({struct_size} bytes)"
                )
                return False

            ctypes.memmove(
                ctypes.addressof(var_struct), c_struct_bytes, len(c_struct_bytes)
            )

            logger.debug(
                f"Injected {len(c_struct_bytes)} bytes into HID_REPORT_DESCRIPTOR ({struct_size} bytes total)"
            )
            return True

        except OSError as e:
            logger.warning(
                f"Failed to run hid-rdesc-to-c-struct: {e}, skipping HID_REPORT_DESCRIPTOR injection"
            )
            return False
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Failed to convert report descriptor: {e.stderr.decode('utf-8')}"
            )
            return False
        except Exception as e:
            logger.error(f"Failed to inject HID_REPORT_DESCRIPTOR: {e}")
            return False

    @classmethod
    def _load(cls, name: str) -> Self:
        # Our test setup guarantees this works, running things manually is
        # a bit more complicated.
        ld_path = os.environ.get("LD_LIBRARY_PATH")
        assert ld_path is not None

        sofile = Path(ld_path) / f"{name}.so"
        if not sofile.exists():
            pytest.skip(f"Unable to locate {sofile}, assuming this BPF wasn't built")

        sofile_dir = sofile.with_suffix(".so.p")
        if not sofile_dir.exists():
            pytest.skip(
                f"Unable to locate {sofile_dir}, assuming this BPF wasn't built"
            )

        # We recreate the BTF information for every .so so the Btf class knows
        # about our types
        btf = Btf.load(list(sofile_dir.iterdir()))
        for c in [
            HidProbeArgs,
            HidDevice,
            HidBpfCtx,
            BpfTimer,
            BpfWq,
            TestAsyncCb,
            Callbacks,
        ]:
            btf.build_struct(c)
            assert hasattr(c, "_fields_")

        # HidRdescDescriptor is optional - only present in BPFs that use
        # HID_REPORT_DESCRIPTOR
        btf.build_struct(HidRdescDescriptor)

        jsonfile = Path(ld_path) / f"{name}.json"
        if not jsonfile.exists():
            pytest.skip(f"Unable to locate {jsonfile}, assuming this BPF wasn't built")

        # Load the libtest-$BPF.so file first.o, map probe and set_callbacks which
        # have a fixed name.
        #
        # Then try to find the corresponding libtest-$BPF.json file that meson
        # should have generated.
        # Because our actual entry points have custom names we check the json for the
        # right section and then map those we want into fixed-name wrappers, i.e.
        # SEC(HID_BPF_RDESC_FIXUP) becomes self._hid_bpf_rdesc_fixup() which points
        # to the right ctypes function.
        try:
            lib = ctypes.CDLL(sofile.name, use_errno=True)
            assert lib is not None
        except OSError as e:
            pytest.exit(
                f"Error loading the library: {e}. Maybe export LD_LIBRARY_PATH=builddir/test"
            )
        for api in cls._api_prototypes:
            if api.optional and not hasattr(lib, api.name):
                continue
            func = getattr(lib, api.name)
            func.argtypes = api.args
            func.restype = api.return_type
            setattr(lib, api.basename, func)

        maps = {
            ctypes.cast(getattr(lib, m.name), ctypes.c_void_p).value: m
            for m in btf.maps
        }

        try:
            # Only one entry per json file so we're good
            js = json.load(open(jsonfile))[0]
            for program in js["programs"]:

                def register_fun(generic_name):
                    func = getattr(lib, program["name"])
                    func.argtypes = (ctypes.POINTER(HidBpfCtx),)
                    func.restype = c_int
                    setattr(lib, generic_name, func)

                if program["section"].endswith("/hid_bpf_rdesc_fixup") or program[
                    "section"
                ].endswith("/hid_rdesc_fixup"):
                    register_fun("_hid_bpf_rdesc_fixup")
                elif program["section"].endswith("/hid_bpf_device_event") or program[
                    "section"
                ].endswith("/hid_device_event"):
                    register_fun("_hid_bpf_device_event")
        except OSError as e:
            pytest.exit(
                f"Error loading the JSON file: {e}. Unexpected LD_LIBRARY_PATH?"
            )

        return cls(lib, btf, maps)

    @classmethod
    def load(cls, name: str) -> Self:
        """
        Load the given bpf.o file from our tree
        """
        name = f"libtest-{name}"
        if name not in cls._libs:
            cls._libs[name] = cls._load(name)
        instance = cls._libs[name]
        assert instance is not None
        return instance

    def set_callbacks(self, callbacks: Callbacks):
        """
        Set the callbacks to use for the various hid_bpf_* functions that may be
        used by a BPF program. These need to have a matching implementation in
        test-wrapper.c

        For most tests this isn't needed and you can pass the rdesc/report bytes
        directly to hid_bpf_rdesc_fixup() or hid_bpf_device_event().
        """
        self.lib._set_callbacks(callbacks)

    def probe(
        self,
        probe_args: HidProbeArgs,
        private_data: PrivateTestData | None = None,
    ) -> HidProbeArgs:
        """Call the BPF program's probe() function"""
        if private_data is None:
            private_data = PrivateTestData(bpf=self)

        callbacks = Callbacks(private_data)
        self.set_callbacks(callbacks)

        # We copy so our caller's probe args are separate from
        # the ones we return after the BPF program modifies them.
        pa = HidProbeArgs()
        p1 = ctypes.byref(probe_args)
        p2 = ctypes.byref(pa)
        ctypes.memmove(p2, p1, ctypes.sizeof(HidProbeArgs))
        pa.hid = callbacks.private_data.id

        # Extract rdesc bytes from probe_args and inject parsed descriptor if needed
        rdesc_size = probe_args.rdesc_size
        if rdesc_size > 0:
            rdesc_bytes = bytes(probe_args.rdesc[:rdesc_size])
            logger.info(f"Injecting {rdesc_size} byte report descriptor before probe")
            injected = self.inject_report_descriptor(rdesc_bytes)
            logger.info(f"Injection {'succeeded' if injected else 'skipped/failed'}")
            if not injected:
                self.clear_report_descriptor()
        else:
            self.clear_report_descriptor()

        rc = self.lib._probe(ctypes.byref(pa))
        if rc != 0:
            raise OSError(rc)
        return pa

    def hid_bpf_device_event(
        self,
        report: bytes | str | None = None,
        private_data: PrivateTestData | None = None,
    ) -> None | bytes:
        """
        Call the BPF program's hid_bpf_device_event function.

        If a report is given, it returns the (possibly modified) report.
        Otherwise it returns None.

        If the report is given with a string representation, it returns
        a string representation as well instead of a byte array.
        """
        if private_data is None:
            private_data = PrivateTestData(bpf=self)

        ctx = private_data.current_ctx

        input_is_binary = isinstance(report, bytes) or isinstance(report, bytearray)

        if report is not None:
            binary_report = (
                report
                if input_is_binary
                else binascii.unhexlify(report.replace(" ", ""))
            )
            allocated_size = int(len(binary_report) / 64 + 1) * 64
            data = (ctypes.c_uint8 * allocated_size)(*binary_report)
            callbacks = Callbacks(private_data)
            callbacks.hid_bpf_data = data
            callbacks.hid_bpf_data_sz = allocated_size
            ctx.allocated_size = allocated_size
            ctx.size = len(binary_report)
            self.set_callbacks(callbacks)
        else:
            data = None

        rc = self.lib._hid_bpf_device_event(ctypes.byref(ctx))
        if rc < 0:
            raise OSError(-rc)

        if rc > 0:
            ctx.retval = rc

        if report is None:
            return None
        assert data is not None

        if input_is_binary:
            return bytes(data[: ctx.retval])

        return binascii.hexlify(bytes(data[: ctx.retval]), " ").decode()

    def hid_bpf_rdesc_fixup(
        self,
        rdesc: bytes | str | None = None,
        private_data: PrivateTestData | None = None,
    ) -> None | bytes:
        """
        Call the BPF program's hid_bpf_rdesc_fixup function.

        If an rdesc is given, it returns the (possibly modified) rdesc.
        Otherwise it returns None.

        If the rdesc is given with a string representation, it returns
        a string representation as well instead of a byte array.
        """
        if private_data is None:
            private_data = PrivateTestData(bpf=self)

        ctx = private_data.current_ctx

        input_is_binary = isinstance(rdesc, bytes) or isinstance(rdesc, bytearray)

        if rdesc is not None:
            binary_rdesc = (
                rdesc if input_is_binary else binascii.unhexlify(rdesc.replace(" ", ""))
            )
            allocated_size = 4096
            data = (ctypes.c_uint8 * allocated_size)(*binary_rdesc)
            callbacks = Callbacks(private_data)
            callbacks.hid_bpf_data = data
            callbacks.hid_bpf_data_sz = allocated_size
            ctx.allocated_size = allocated_size
            ctx.size = len(binary_rdesc)
            self.set_callbacks(callbacks)
        else:
            data = None

        rc = self.lib._hid_bpf_rdesc_fixup(ctypes.byref(ctx))
        if rc < 0:
            raise OSError(rc)

        if rc > 0:
            ctx.retval = rc

        if rdesc is None:
            return None
        assert data is not None

        if input_is_binary:
            return bytes(data[: ctx.retval])

        return binascii.hexlify(bytes(data[: ctx.retval]), " ").decode()
