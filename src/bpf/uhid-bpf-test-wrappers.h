/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2024 Benjamin Tissoires
 */

#ifndef __UHID_BPF_TEST_WRAPPERS_H
#define __UHID_BPF_TEST_WRAPPERS_H

#include <bpf/bpf_tracing.h>

#undef bpf_printk
#include <stdio.h>
#define bpf_printk(fmt, args...) printf(fmt "\n", ##args)

/* BPF_PROG is a macro that creates the function with only
 * a context as an argument, and deal with the extra parameters
 * through some bpf magic. For testing, make it simple
 */
#undef BPF_PROG
#define BPF_PROG(name, args...) name(args)

#undef bpf_for
#define bpf_for(i, start, end) \
	for (i = (start); i < (end); i++)

typedef int (*hid_bpf_async_callback_t)(void *map, int *key, void *value);

/* below are BPF helpers: they are stored as an enum and
 * directly called as if it were their address.
 * This works in BPF because the bpf target knows about them,
 * but in plain C, we consider them to be a function, and we
 * crash.
 *
 * We do a 2 steps operation:
 * - first we mask the helper name
 * - then we define and extern function, which needs to be
 *   properly defined in test-wrapper.c
 */

#define bpf_map_lookup_elem bpf_map_lookup_elem__hid_bpf
extern void *bpf_map_lookup_elem(void *map, const void *key);

#define bpf_map_pop_elem bpf_map_pop_elem__hid_bpf
extern int bpf_map_pop_elem(void *map, void *data);

#define bpf_map_push_elem bpf_map_push_elem__hid_bpf
extern int bpf_map_push_elem(void *map, void *data, uint64_t flags);

#define bpf_spin_lock(a) bpf_spin_lock__hid_bpf(a)
extern void bpf_spin_lock(void *);

#define bpf_spin_unlock bpf_spin_unlock__hid_bpf
extern void bpf_spin_unlock(void *);

#define bpf_timer_init bpf_timer_init__hid_bpf
extern int bpf_timer_init(void *, void *, int);

#define bpf_timer_set_callback bpf_timer_set_callback__hid_bpf
extern int bpf_timer_set_callback(void *, hid_bpf_async_callback_t);

#define bpf_timer_start bpf_timer_start__hid_bpf
extern int bpf_timer_start(void *, int, int);

#endif /* __UHID_BPF_TEST_WRAPPERS_H */
