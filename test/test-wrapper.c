// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <vmlinux.h>

#include "hid_report_descriptor_helpers.h"

typedef int (*hid_bpf_async_callback_t)(void *map, int *key, void *value);

/* Dummy variables to force BTF inclusion of types needed by our pytests */
static struct bpf_timer __attribute__((unused)) __btf_bpf_timer;
static struct hid_rdesc_descriptor __attribute__((unused)) __btf_hid_rdesc_descriptor;

struct test_async_cb {
	void *map;
	int key;
	void *value;
	hid_bpf_async_callback_t cb;
};

#define MAX_PENDING_TIMERS 16

static struct {
	struct test_async_cb cb;
	int delay;
	void *timer_p;
} pending_timers[MAX_PENDING_TIMERS];

static int num_pending_timers;
static int execution_depth;

static struct test_callbacks {
	int (*hid_bpf_allocate_context)(struct test_callbacks *callbacks, unsigned int hid);
	void (*hid_bpf_release_context)(struct test_callbacks *callbacks, void* ctx);
	int (*hid_bpf_hw_request)(struct test_callbacks *callbacks,
				  struct hid_bpf_ctx *ctx,
				  uint8_t *data,
				  size_t buf__sz,
				  int type,
				  int reqtype);
	int (*hid_bpf_hw_output_report)(struct test_callbacks *callbacks,
					struct hid_bpf_ctx *ctx,
					__u8 *buf, size_t buf__sz);
	int (*bpf_map_lookup_elem)(struct test_callbacks *callbacks, void *map,
				   const void *key);
	int (*bpf_map_pop_elem)(struct test_callbacks *callbacks, void *map, void *data);
	int (*bpf_map_push_elem)(struct test_callbacks *callbacks, void *map, void *data, uint64_t flags);
	int (*bpf_timer_init)(struct test_callbacks *callbacks, void *timer, void *map, unsigned int flags);
	int (*async_set_callback)(struct test_callbacks *callbacks, void *timer, void* cb);
	int (*async_start)(struct test_callbacks *callbacks, void *timer,
			       int delay, int flags);
	int (*bpf_wq_init)(struct test_callbacks *callbacks, void *wq, void *map, int clock);
	int (*bpf_iter_num_new)(struct test_callbacks *callbacks, void *it, int start, int end);
	void *(*bpf_iter_num_next)(struct test_callbacks *callbacks, void *it);
	int (*bpf_iter_num_destroy)(struct test_callbacks *callbacks, void *it);
	int (*hid_bpf_input_report)(struct test_callbacks *callbacks,
				    struct hid_bpf_ctx *ctx,
				    int type, uint8_t *data, uint32_t len);
	/* The data returned by hid_bpf_get_data */
	uint8_t *hid_bpf_data;
	size_t hid_bpf_data_sz;
	/* The data returned by hid_bpf_allocate_context */
	struct hid_bpf_ctx *ctx;
	/* meaningful in python only */
	void *private_data;
	/* various helpers/kfuncs return value */
	void *helpers_retval;
	/* the virtual time of events */
	unsigned long long int time;
} callbacks;

void set_callbacks(struct test_callbacks *cb)
{
	callbacks = *cb;
}

uint8_t* hid_bpf_get_data(struct hid_bpf_ctx *ctx, unsigned int offset, size_t sz)
{
	/* we are not relying on ctx->allocated_size because the
	 * value might be overwritten by the bpf program (though
	 * arguably the value is read only in the kernel)
	 */
	if (offset + sz <= callbacks.hid_bpf_data_sz)
		return callbacks.hid_bpf_data + offset;
	else
		return NULL;
}

struct hid_bpf_ctx *hid_bpf_allocate_context(unsigned int hid)
{
	int ret = callbacks.hid_bpf_allocate_context(&callbacks, hid);

	if (ret)
		return NULL;

	return callbacks.ctx;
}

void hid_bpf_release_context(struct hid_bpf_ctx *ctx)
{
	callbacks.hid_bpf_release_context(&callbacks, ctx);
}

int hid_bpf_hw_request(struct hid_bpf_ctx *ctx,
		       __u8 *data,
		       size_t buf__sz,
		       enum hid_report_type type,
		       enum hid_class_request reqtype)
{
	return callbacks.hid_bpf_hw_request(&callbacks, ctx, data, buf__sz, type, reqtype);
}

int hid_bpf_hw_output_report(struct hid_bpf_ctx *ctx,
			     __u8 *buf, size_t buf__sz)
{
	return callbacks.hid_bpf_hw_output_report(&callbacks, ctx, buf, buf__sz);
}

int bpf_wq_set_callback_impl(struct bpf_wq *wq, hid_bpf_async_callback_t cb,
			     unsigned int flags__k, void *aux__ign)
{
	return callbacks.async_set_callback(&callbacks, wq, cb);
}

int bpf_wq_init(struct bpf_wq *wq, void *p__map, unsigned int flags)
{
	return callbacks.bpf_wq_init(&callbacks, wq, p__map, flags);
}

int bpf_wq_start(struct bpf_wq *wq, unsigned int flags)
{
	struct test_async_cb *async_cb;
	int err;

	err = callbacks.async_start(&callbacks, wq, 0, flags);
	if (err)
		return err;

	async_cb = (struct test_async_cb *)callbacks.helpers_retval;
	execution_depth++;
	async_cb->cb(async_cb->map, &async_cb->key, async_cb->value);
	execution_depth--;

	return 0;
}

void *bpf_map_lookup_elem__hid_bpf(struct bpf_map *map, const void *key)
{
	int err;

	err = callbacks.bpf_map_lookup_elem(&callbacks, map, key);
	if (err)
		return NULL;

	return callbacks.helpers_retval;
}

int bpf_map_pop_elem__hid_bpf(struct bpf_map *map, void *data)
{
	return callbacks.bpf_map_pop_elem(&callbacks, map, data);
}

int bpf_map_push_elem__hid_bpf(struct bpf_map *map, void *data, uint64_t flags)
{
	return callbacks.bpf_map_push_elem(&callbacks, map, data, flags);
}

void bpf_spin_lock__hid_bpf(void* lock)
{
}

void bpf_spin_unlock__hid_bpf(void* lock)
{
}

int bpf_timer_init__hid_bpf(void *timer, void *map, int clock)
{
	return callbacks.bpf_timer_init(&callbacks, timer, map, clock);
}

int bpf_timer_set_callback__hid_bpf(void *timer, hid_bpf_async_callback_t cb)
{
	return callbacks.async_set_callback(&callbacks, timer, cb);
}

static bool remove_pending_timer(void *timer)
{
	int i;

	for (i = 0; i < num_pending_timers; i++) {
		if (pending_timers[i].timer_p == timer) {
			num_pending_timers--;
			if (i != num_pending_timers)
				pending_timers[i] = pending_timers[num_pending_timers];
			return true;
		}
	}

	return false;
}

int bpf_timer_start__hid_bpf(void *timer, int delay, int flags)
{
	struct test_async_cb *async_cb;
	unsigned long long int current_time;
	int err;

	err = callbacks.async_start(&callbacks, timer, delay, flags);
	if (err)
		return err;

	async_cb = (struct test_async_cb *)callbacks.helpers_retval;

	/* Remove any previous pending entry for this timer */
	remove_pending_timer(timer);

	if (execution_depth > 0 && delay > 0) {
		/* Queue for later — don't fire inside nested execution */
		if (num_pending_timers < MAX_PENDING_TIMERS) {
			pending_timers[num_pending_timers].cb = *async_cb;
			pending_timers[num_pending_timers].delay = delay;
			pending_timers[num_pending_timers].timer_p = timer;
			num_pending_timers++;
		}
		return 0;
	}

	current_time = callbacks.time;
	callbacks.time += (delay / 1000 / 1000); /* delay is in nanoseconds, we care only about milliseconds */

	async_cb->cb(async_cb->map, &async_cb->key, async_cb->value);

	/* reset our time to the previous value */
	callbacks.time = current_time;

	return 0;
}

int bpf_timer_cancel__hid_bpf(void *timer)
{
	return remove_pending_timer(timer) ? 0 : 1;
}

int hid_bpf_input_report(struct hid_bpf_ctx *ctx,
			 enum hid_report_type type,
			 __u8 *buf, size_t len)
{
	if (!callbacks.hid_bpf_input_report)
		return 0;

	return callbacks.hid_bpf_input_report(&callbacks, ctx, type, buf, len);
}

int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end)
{
	return callbacks.bpf_iter_num_new(&callbacks, it, start, end);
}

int *bpf_iter_num_next(struct bpf_iter_num *it)
{
	return (int *)callbacks.bpf_iter_num_next(&callbacks, it);
}

void bpf_iter_num_destroy(struct bpf_iter_num *it)
{
	callbacks.bpf_iter_num_destroy(&callbacks, it);
}
