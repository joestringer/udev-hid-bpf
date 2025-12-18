#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 Red Hat

from ctypes import (
    c_uint32,
    c_int32,
    c_void_p,
)
from typing import Optional, Tuple, Type, Self
from dataclasses import dataclass
from enum import IntEnum

import ctypes
import pytest
import types


# see include/linux/uapi/btf.h
# struct btf_type {
#         __u32 name_off;
#         /* "info" bits arrangement
#          * bits  0-15: vlen (e.g. # of struct's members)
#          * bits 16-23: unused
#          * bits 24-28: kind (e.g. int, ptr, array...etc)
#          * bits 29-30: unused
#          * bit     31: kind_flag, currently used by
#          *             struct, union, enum, fwd and enum64
#          */
#         __u32 info;
#         /* "size" is used by INT, ENUM, STRUCT, UNION, DATASEC and ENUM64.
#          * "size" tells the size of the type it is describing.
#          *
#          * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
#          * FUNC, FUNC_PROTO, VAR, DECL_TAG and TYPE_TAG.
#          * "type" is a type_id referring to another type.
#          */
#         union {
#                 __u32 size;
#                 __u32 type;
#         };
# };
class _U(ctypes.Union):
    _fields_ = [
        ("size", c_uint32),
        ("type", c_uint32),
    ]


class BtfType(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("name_off", c_uint32),
        ("info", c_uint32),
        ("u", _U),
    ]

    @property
    def vlen(self):
        """#define BTF_INFO_VLEN(info)     ((info) & 0xffff)"""
        return self.info & 0xFFFF

    @property
    def kind(self):
        """#define BTF_INFO_KIND(info)     (((info) >> 24) & 0x1f)"""
        return (self.info >> 24) & 0x1F

    @property
    def kflag(self):
        """#define BTF_INFO_KFLAG(info)    ((info) >> 31)"""
        return self.info >> 31

    @property
    def size(self):
        """tells the size of the type it is describing
        (used by INT, ENUM, STRUCT, UNION and ENUM64)."""
        assert self.kind in (
            BtfKind.INT,
            BtfKind.ENUM,
            BtfKind.STRUCT,
            BtfKind.UNION,
            BtfKind.ENUM64,
        )
        return self.u.size

    @property
    def type_id(self):
        """reference to another type
        (used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
        FUNC, FUNC_PROTO, DECL_TAG and TYPE_TAG)."""
        assert self.kind in (
            BtfKind.PTR,
            BtfKind.TYPEDEF,
            BtfKind.VOLATILE,
            BtfKind.CONST,
            BtfKind.RESTRICT,
            BtfKind.FUNC,
            BtfKind.FUNC_PROTO,
            BtfKind.DECL_TAG,
            BtfKind.TYPE_TAG,
        )
        return self.u.type


class BtfKind(IntEnum):
    UNKN = 0  # Unknown
    INT = 1  # Integer
    PTR = 2  # Pointer
    ARRAY = 3  # Array
    STRUCT = 4  # Struct
    UNION = 5  # Union
    ENUM = 6  # Enumeration up to 32-bit values
    FWD = 7  # Forward
    TYPEDEF = 8  # Typedef
    VOLATILE = 9  # Volatile
    CONST = 10  # Const
    RESTRICT = 11  # Restrict
    FUNC = 12  # Function
    FUNC_PROTO = 13  # Function Proto
    VAR = 14  # Variable
    DATASEC = 15  # Section
    FLOAT = 16  # Floating point
    DECL_TAG = 17  # Decl Tag
    TYPE_TAG = 18  # Type Tag
    ENUM64 = 19  # Enumeration up to 64-bit values


# /* BTF_KIND_STRUCT and BTF_KIND_UNION are followed
#  * by multiple "struct btf_member".  The exact number
#  * of btf_member is stored in the vlen (of the info in
#  * "struct btf_type").
#  */
# struct btf_member {
#         __u32   name_off;
#         __u32   type;
#         /* If the type info kind_flag is set, the btf_member offset
#          * contains both member bitfield size and bit offset. The
#          * bitfield size is set for bitfield members. If the type
#          * info kind_flag is not set, the offset contains only bit
#          * offset.
#          */
#         __u32   offset;
# };
class BtfMember(ctypes.Structure):
    _fields_ = [
        ("name_off", c_uint32),
        ("type", c_uint32),
        ("offset", c_uint32),
    ]

    # /* If the struct/union type info kind_flag is set, the
    #  * following two macros are used to access bitfield_size
    #  * and bit_offset from btf_member.offset.
    #  */
    @property
    def bitfield_size(self):
        return self.offset >> 24

    @property
    def bit_offset(self):
        return self.offset & 0xFFFFFF


# /* BTF_KIND_ARRAY is followed by one "struct btf_array" */
# struct btf_array {
# 	__u32	type;
# 	__u32	index_type;
# 	__u32	nelems;
# };
class BtfArray(ctypes.Structure):
    _fields_ = [
        ("type", c_uint32),
        ("index_type", c_uint32),
        ("nelems", c_uint32),
    ]


# /* BTF_KIND_FUNC_PROTO is followed by multiple "struct btf_param".
#  * The exact number of btf_param is stored in the vlen (of the
#  * info in "struct btf_type").
#  */
# struct btf_param {
# 	__u32	name_off;
# 	__u32	type;
# };
class BtfParam(ctypes.Structure):
    _fields_ = [
        ("name_off", c_uint32),
        ("type", c_uint32),
    ]


# /* BTF_KIND_DATASEC is followed by multiple "struct btf_var_secinfo"
#  * to describe all BTF_KIND_VAR types it contains along with it's
#  * in-section offset as well as size.
#  */
# struct btf_var_secinfo {
# 	__u32	type;
# 	__u32	offset;
# 	__u32	size;
# };
class BtfVarSecinfo(ctypes.Structure):
    _fields_ = [
        ("type", c_uint32),
        ("offset", c_uint32),
        ("size", c_uint32),
    ]


@dataclass
class Api:
    """
    Wrapper to make automatically loading functions from a .so file simpler.
    """

    name: str
    args: Tuple[Type[ctypes._SimpleCData | ctypes._Pointer], ...]
    return_type: Optional[Type[ctypes._SimpleCData | ctypes._Pointer]]


@dataclass
class Map:
    name: str
    ctype: type


class Btf:
    # Cached libbpf .so file
    _lib: ctypes.CDLL | None = None

    # Cached per .so btf files
    _btfs: dict[str, Self] = {}

    _btf_api_prototypes: list[Api] = [
        Api(
            name="btf__load_vmlinux_btf",
            args=(),
            return_type=c_void_p,
        ),
        Api(
            name="btf__new_empty",
            args=(),
            return_type=c_void_p,
        ),
        Api(
            name="btf__parse",
            args=(ctypes.c_char_p, c_void_p),
            return_type=c_void_p,
        ),
        Api(
            name="btf__add_btf",
            args=(c_void_p, c_void_p),
            return_type=c_int32,
        ),
        Api(
            name="btf__find_by_name",
            args=(c_void_p, ctypes.c_char_p),
            return_type=c_int32,
        ),
        Api(
            name="btf__type_by_id",
            args=(c_void_p, c_uint32),
            return_type=c_void_p,
        ),
        Api(
            name="btf__name_by_offset",
            args=(c_void_p, c_uint32),
            return_type=ctypes.c_char_p,
        ),
    ]

    def __init__(self, name: str, lib: ctypes.CDLL, btf: c_void_p):
        self.lib = lib
        self.name = name
        self.btf = btf
        self.known_types: dict[str, ctypes.Structure | ctypes.Union] = {}
        self.ignore_types: list[ctypes.Structure | ctypes.Union] = []
        Btf._btfs[name] = self

    @classmethod
    def load(cls, btf_files: None | list[str] = None) -> Self:
        """
        Load BTF from the running kernel
        """
        if cls._lib is None:
            cls._lib = cls._load_libbpf(btf_files)

        name = btf_files[0].parent.stem if btf_files is not None else "vmlinux"

        instance = cls._btfs.get(name, cls._load(name, btf_files))
        assert instance is not None
        return instance

    @classmethod
    def _load_libbpf(cls, btf_files: None | list[str]) -> Self:
        try:
            libbpf = ctypes.CDLL("libbpf.so", use_errno=True)
            assert libbpf is not None
        except OSError as e:
            pytest.exit(
                f"Error loading the library: {e}. Maybe libbpf is not installed?"
            )
        for api in Btf._btf_api_prototypes:
            fun = getattr(libbpf, api.name)
            fun.argtypes = api.args
            fun.restype = api.return_type
        return libbpf

    @classmethod
    def _load(cls, name: str, btf_files: None | list[str]) -> Self:
        libbpf = cls._lib
        if btf_files is None:
            _btf = c_void_p(libbpf.btf__load_vmlinux_btf())
        else:
            _btf = c_void_p(libbpf.btf__new_empty())
            for btf_file in btf_files:
                btf = c_void_p(libbpf.btf__parse(bytes(btf_file), c_void_p(None)))
                err = libbpf.btf__add_btf(_btf, btf)
                assert err >= 0

        assert _btf.value is not None
        return cls(name, libbpf, _btf)

    def get_type(self, name, type_id, from_pointer=False):
        btf = self.btf
        libbpf = self.lib
        btf_to_ctypes = {
            b"_Bool": ctypes.c_bool,
            b"char": ctypes.c_char,
            b"signed char": ctypes.c_char,
            b"unsigned char": ctypes.c_ubyte,
            b"short int": ctypes.c_short,
            b"short unsigned int": ctypes.c_ushort,
            b"int": ctypes.c_int,
            b"unsigned int": ctypes.c_uint,
            b"long int": ctypes.c_long,
            b"long unsigned int": ctypes.c_ulong,
            b"long long int": ctypes.c_longlong,
            b"long long unsigned int": ctypes.c_ulonglong,
            b"__int128 unsigned": ctypes.c_longlong * 2,
            b"size_t": ctypes.c_size_t,
        }

        m_type_p = libbpf.btf__type_by_id(btf, type_id)
        if not m_type_p:
            return None

        m_type = BtfType.from_address(m_type_p)
        m_type_name = libbpf.btf__name_by_offset(btf, m_type.name_off)
        kind = m_type.kind

        if kind == BtfKind.UNKN:
            return None

        elif kind == BtfKind.INT:
            # basic type in C
            return btf_to_ctypes[m_type_name]

        elif kind == BtfKind.PTR:
            # pointer: if we get a new type behind that pointer, the
            # new type will not be recursively populated
            val_type = self.get_type(name, m_type.type, from_pointer=True)
            fun_type = ctypes.CFUNCTYPE(None)
            if val_type is None:
                return ctypes.c_void_p
            elif isinstance(val_type, type(fun_type)):
                return val_type
            return ctypes.POINTER(val_type)

        elif kind == BtfKind.ARRAY:
            # int[length]
            array_info = BtfArray.from_address(m_type_p + ctypes.sizeof(BtfType))
            return self.get_type(name, array_info.type) * array_info.nelems

        elif kind in [BtfKind.STRUCT, BtfKind.UNION]:
            # recursively go down the struct or union if we are not coming
            # from a pointer
            name = m_type_name.decode()
            if not name:
                name = f"anon_{type_id}"

            cls = self.known_types.get(name, None)
            if cls is not None and hasattr(cls, "_fields_"):
                # the type is already fully known, return
                return cls

            elif cls is None:
                # new struct/union, allocate a new class
                parent = ctypes.Structure if kind == BtfKind.STRUCT else ctypes.Union
                camelCaseName = "".join([word.capitalize() for word in name.split("_")])
                cls = types.new_class(camelCaseName, (parent,))
                cls.cname = name
                self.known_types[name] = cls

            if from_pointer:
                return cls

            MEMBERS = BtfMember * m_type.vlen
            arg_members = MEMBERS.from_address(m_type_p + ctypes.sizeof(BtfType))

            fields = []
            anonymous = []
            unique_id = 0
            kind_flag = m_type.kflag
            for member in arg_members:
                name = libbpf.btf__name_by_offset(btf, member.name_off).decode()
                ctype = None

                if not name:
                    # if we have an anonymous field, register it
                    name = f"u_{unique_id}"
                    unique_id += 1
                    ctype = self.get_type(name, member.type)
                    anonymous.append(name)
                elif (
                    hasattr(cls, "_fields_overrides_")
                    and name in cls._fields_overrides_
                ):
                    ctype = cls._fields_overrides_[name]
                else:
                    ctype = self.get_type(name, member.type)

                assert ctype is not None

                # some ints have a bitfield size, ensure we don't mess up
                if not kind_flag or not member.bitfield_size:
                    fields.append((name, ctype))
                else:
                    fields.append((name, ctype, member.bitfield_size))

            if anonymous:
                cls._anonymous_ = anonymous
            cls._fields_ = fields
            cls.btftype = m_type
            cls.btfsize = property(lambda self: self.btftype.size)

            return cls

        elif kind == BtfKind.ENUM:
            # enums are translated to int, long, etc based on the size parameter
            size = m_type.size * 8
            return getattr(ctypes, f"c_uint{size}")

        elif kind == BtfKind.FWD:
            # Forward are types that are not loaded yet, so we can't
            # type them
            return None

        elif kind == BtfKind.TYPEDEF:
            # typedefs are like int, but we might have specifics in ctypes,
            # so look in btf_to_ctypes first.
            return btf_to_ctypes.get(
                m_type_name, self.get_type(m_type_name, m_type.type)
            )

        elif kind in [BtfKind.VOLATILE, BtfKind.CONST]:
            # modifier, just forward the child type
            return self.get_type(name, m_type.type, from_pointer)

        elif kind == BtfKind.FUNC_PROTO:
            ret_type = self.get_type(name, m_type.type)
            ARGS = BtfParam * m_type.vlen
            args = ARGS.from_address(m_type_p + ctypes.sizeof(BtfType))
            params = [
                self.get_type(libbpf.btf__name_by_offset(btf, a.name_off), a.type)
                for a in args
            ]
            # special case `int fun(void)`
            if len(params) == 1 and params[0] is None:
                params = []
            return ctypes.CFUNCTYPE(ret_type, *params)

        else:
            raise Exception(f"unsupported btf kind {kind} for {name}")

    def build_struct(self, cls):
        """
        Take the given ctypes class, look for its definition in the btf
        and populate its _fields_ field.

        Note that this allows forward declaration of pointers, thus if
        a struct is expected to have a pointer and we need to dereference
        it, the pointed struct must be build first.
        """
        btf = self.btf
        libbpf = self.lib
        cname = cls.cname

        if cname not in self.known_types:
            self.known_types[cname] = cls

        if hasattr(cls, "_fields_"):
            return

        self.get_type(cname, libbpf.btf__find_by_name(btf, cname.encode()))

    @property
    def maps(self):
        btf = self.btf
        libbpf = self.lib
        type_id = libbpf.btf__find_by_name(btf, ".maps".encode())
        if type_id < 0:
            return []

        m_type_p = libbpf.btf__type_by_id(btf, type_id)
        m_type = BtfType.from_address(m_type_p)
        kind = m_type.kind

        assert kind == BtfKind.DATASEC

        if m_type.vlen == 0:
            return []

        MAPS = BtfVarSecinfo * m_type.vlen
        maps = MAPS.from_address(m_type_p + ctypes.sizeof(BtfType))

        maps_types = [
            BtfType.from_address(libbpf.btf__type_by_id(btf, m.type)) for m in maps
        ]

        retval = []

        for m in maps_types:
            map_name = libbpf.btf__name_by_offset(btf, m.name_off).decode()
            type_id = m.type

            ctype = self.get_type("", type_id)
            value = [f[1] for f in ctype._fields_ if f[0] == "value"][0]

            retval.append(Map(map_name, value._type_))

        return retval
