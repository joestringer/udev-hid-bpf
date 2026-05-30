#!/usr/bin/env fish

#NAME=SIMAGIC_SIMTRANSFER
#PROG=0010-Simagic__SimTransfer.bpf
set NAME "One Handle MasCon for Nintendo Switch"
set PROG "0010-Zuiki__Mascon.bpf"

set -l device $(udev-hid-bpf list-devices \
                | yq -r '.devices | filter(.name == "'"$NAME"'")[0].syspath')
set -l source 'src/bpf/testing/'"$PROG"'.c'
set -l build '../build/src/bpf/'"$PROG"'.o'

watchdo $source \
    "meson compile -C ../build \
    && sudo udev-hid-bpf --verbose remove $device \
    && sudo udev-hid-bpf --verbose add $device $build"
