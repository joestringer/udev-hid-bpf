#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 Red Hat

"""
Shared pytest fixtures for BPF testing.
"""

from . import Bpf
import pytest


@pytest.fixture
def bpf(source: str):
    """
    A fixture that allows parametrizing over a number of sources. Use with e.g.::

        @pytest.mark.parametrize("source", ["0010-FR-TEC__Raptor-Mach-2"])
        def test_something(bpf):
            pass
    """
    assert source is not None
    bpf = Bpf.load(source)
    assert bpf is not None
    yield bpf
