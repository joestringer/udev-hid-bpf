# tracing_sources are compatible with kernel v6.3+
#
# These files do not require features only available
# in the newer struct_ops approach and are thus compatible
# for both approaches.
tracing_sources = [
    '0010-Logitech__SpaceNavigator.bpf.c',
    '0010-Huion__Kamvas13Gen3.bpf.c',
    '0010-Huion__Kamvas16Gen3.bpf.c',
    '0030-Huion__Kamvas-Pro-19.bpf.c',
    '0010-XPPen__Deco01V3.bpf.c',
    '0010-WALTOP__Batteryless-Tablet.bpf.c',
    '0010-XPPen__Deco02.bpf.c'
]

# 'sources' are BPF programs only compatible with
# struct_ops (kernel v6.11+)
sources = [
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
