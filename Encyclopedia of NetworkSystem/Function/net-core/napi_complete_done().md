---
Parameter:
  - int
  - napi_struct
Return: bool
Location: /net/core/dev.c
---

```c title=napi_complete_done()
bool napi_complete_done(struct napi_struct *n, int work_done)
{
	unsigned long flags, val, new, timeout = 0;
	bool ret = true;

	/*
	 * 1) Don't let napi dequeue from the cpu poll list
	 *    just in case its running on a different cpu.
	 * 2) If we are busy polling, do nothing here, we have
	 *    the guarantee we will be called later.
	 */
	if (unlikely(n->state & (NAPIF_STATE_NPSVC |
				 NAPIF_STATE_IN_BUSY_POLL)))
		return false;

	if (work_done) {
		if (n->gro_bitmask)
			timeout = READ_ONCE(n->dev->gro_flush_timeout);
		n->defer_hard_irqs_count = READ_ONCE(n->dev->napi_defer_hard_irqs);
	}
	if (n->defer_hard_irqs_count > 0) {
		n->defer_hard_irqs_count--;
		timeout = READ_ONCE(n->dev->gro_flush_timeout);
		if (timeout)
			ret = false;
	}
	if (n->gro_bitmask) {
		/* When the NAPI instance uses a timeout and keeps postponing
		 * it, we need to bound somehow the time packets are kept in
		 * the GRO layer
		 */
		napi_gro_flush(n, !!timeout);
	}

	gro_normal_list(n); // [[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_list().md|gro_normal_list()]]

	if (unlikely(!list_empty(&n->poll_list))) {
		/* If n->poll_list is not empty, we need to mask irqs */
		local_irq_save(flags);
		list_del_init(&n->poll_list);
		local_irq_restore(flags);
	}
	WRITE_ONCE(n->list_owner, -1);

	val = READ_ONCE(n->state);
	do {
		WARN_ON_ONCE(!(val & NAPIF_STATE_SCHED));

		new = val & ~(NAPIF_STATE_MISSED | NAPIF_STATE_SCHED |
			      NAPIF_STATE_SCHED_THREADED |
			      NAPIF_STATE_PREFER_BUSY_POLL);

		/* If STATE_MISSED was set, leave STATE_SCHED set,
		 * because we will call napi->poll() one more time.
		 * This C code was suggested by Alexander Duyck to help gcc.
		 */
		new |= (val & NAPIF_STATE_MISSED) / NAPIF_STATE_MISSED *
						    NAPIF_STATE_SCHED;
	} while (!try_cmpxchg(&n->state, &val, new));

	if (unlikely(val & NAPIF_STATE_MISSED)) {
		__napi_schedule(n);
		return false;
	}

	if (timeout)
		hrtimer_start(&n->timer, ns_to_ktime(timeout),
			      HRTIMER_MODE_REL_PINNED);
	return ret;
}
EXPORT_SYMBOL(napi_complete_done);
```

[[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_list().md|gro_normal_list()]]

> napi가 잘 되었는지 확인하고 기타 작업을 처리하는 함수. gro_bitmask와 defer_hard_irqs_count등을 확인하여 timeout관련 처리를 하고, 만약 gro_bitmask가 존재한다면 `napi_gro_flush()`를 실행하게 됨. 이후 `gro_normal_list(n)`을 하게 됨. 만약 NAPIF_STATE_MISSED가 있다면 다시 `__napi_schedule(n)`을 통해 napi가 실행 될 수 있도록 함.