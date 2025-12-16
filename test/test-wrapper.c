// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <vmlinux.h>

typedef int (*hid_bpf_async_callback_t)(void *map, int *key, void *value);

struct test_async_cb {
	void *map;
	int key;
	void *value;
	hid_bpf_async_callback_t cb;
};

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
	int (*bpf_timer_init)(struct test_callbacks *callbacks, void *timer, void *map, unsigned int flags);
	int (*async_set_callback)(struct test_callbacks *callbacks, void *timer, void* cb);
	int (*async_start)(struct test_callbacks *callbacks, void *timer,
			       int delay, int flags);
	int (*bpf_wq_init)(struct test_callbacks *callbacks, void *wq, void *map, int clock);
	int (*bpf_iter_num_new)(struct test_callbacks *callbacks, void *it, int start, int end);
	void *(*bpf_iter_num_next)(struct test_callbacks *callbacks, void *it);
	int (*bpf_iter_num_destroy)(struct test_callbacks *callbacks, void *it);
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

void* hid_bpf_allocate_context(unsigned int hid)
{
	int ret = callbacks.hid_bpf_allocate_context(&callbacks, hid);

	if (ret)
		return NULL;

	return callbacks.ctx;
}

void hid_bpf_release_context(void* ctx)
{
	callbacks.hid_bpf_release_context(&callbacks, ctx);
}

int hid_bpf_hw_request(struct hid_bpf_ctx *ctx,
		       uint8_t *data,
		       size_t buf__sz,
		       int type,
		       int reqtype)
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
	async_cb->cb(async_cb->map, &async_cb->key, async_cb->value);

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

int bpf_timer_start__hid_bpf(void *timer, int delay, int flags)
{
	struct test_async_cb *async_cb;
	unsigned long long int current_time;
	int err;

	err = callbacks.async_start(&callbacks, timer, delay, flags);
	if (err)
		return err;

	current_time = callbacks.time;
	callbacks.time += (delay / 1000 / 1000); /* delay is in nanoseconds, we care only about milliseconds */

	async_cb = (struct test_async_cb *)callbacks.helpers_retval;
	async_cb->cb(async_cb->map, &async_cb->key, async_cb->value);

	/* reset our time to the previous value */
	callbacks.time = current_time;

	return 0;
}

int bpf_iter_num_new(void *it, int start, int end)
{
	return callbacks.bpf_iter_num_new(&callbacks, it, start, end);
}

int *bpf_iter_num_next(void *it)
{
	return (int *)callbacks.bpf_iter_num_next(&callbacks, it);
}

void bpf_iter_num_destroy(void *it)
{
	callbacks.bpf_iter_num_destroy(&callbacks, it);
}
