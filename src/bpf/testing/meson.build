# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '0010-Huion__KeydialK20-Bluetooth.bpf.c',
]

# 'sources' are BPF programs only compatible with
# struct_ops (kernel v6.11+)
sources = [
    '0010-Generic__touchpad.bpf.c',
    '0010-Simagic__SimTransfer.bpf.c',
]

foreach bpf: tracing_sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'testing',
            'file': files(bpf)[0],
            'install': install_testing,
            'build_by_default': install_testing,
            'compile_with_tracing': false,
        },
    ]
    if use_bpf_tracing
        bpf_sources += [
            {
                'name': bpf,
                'section': 'testing',
                'file': files(bpf)[0],
                'install': install_testing,
                'build_by_default': install_testing,
                'compile_with_tracing': true,
            },
        ]
    endif
endforeach

foreach bpf: sources
    bpf_sources += [
        {
            'name': bpf,
            'section': 'testing',
            'file': files(bpf)[0],
            'install': install_testing,
            'build_by_default': install_testing,
            'compile_with_tracing': false,
        },
    ]
endforeach
