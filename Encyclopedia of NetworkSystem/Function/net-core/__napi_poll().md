---
Parameter:
  - bool
  - napi_struct
Return: int
Location: /net/core/dev.c
---

```c title=__napi_poll()
static int __napi_poll(struct napi_struct *n, bool *repoll)
{
	int work, weight;

	weight = n->weight;

	/* This NAPI_STATE_SCHED test is for avoiding a race
	 * with netpoll's poll_napi().  Only the entity which
	 * obtains the lock and sees NAPI_STATE_SCHED set will
	 * actually make the ->poll() call.  Therefore we avoid
	 * accidentally calling ->poll() when NAPI is not scheduled.
	 */
	work = 0;
	if (napi_is_scheduled(n)) {
		work = n->poll(n, weight);
		trace_napi_poll(n, work, weight);

		xdp_do_check_flushed(n);
	}

	if (unlikely(work > weight))
		netdev_err_once(n->dev, "NAPI poll function %pS returned %d, exceeding its budget of %d.\n",
				n->poll, work, weight);

	if (likely(work < weight))
		return work;

	/* Drivers must not modify the NAPI state if they
	 * consume the entire weight.  In such cases this code
	 * still "owns" the NAPI instance and therefore can
	 * move the instance around on the list at-will.
	 */
	if (unlikely(napi_disable_pending(n))) {
		napi_complete(n); // [[Encyclopedia of NetworkSystem/Function/include-linux/napi_complete() .md|napi_complete()]]
		return work;
	}

	/* The NAPI context has more processing work, but busy-polling
	 * is preferred. Exit early.
	 */
	if (napi_prefer_busy_poll(n)) { // [[Encyclopedia of NetworkSystem/Function/include-linux/napi_prefer_busy_poll() .md|napi_prefer_busy_poll()]]
		if (napi_complete_done(n, work)) { // [[Encyclopedia of NetworkSystem/Function/net-core/napi_complete_done().md|napi_complete_done()]]
			/* If timeout is not set, we need to make sure
			 * that the NAPI is re-scheduled.
			 */
			napi_schedule(n);
		}
		return work;
	}

	if (n->gro_bitmask) {
		/* flush too old packets
		 * If HZ < 1000, flush all packets.
		 */
		napi_gro_flush(n, HZ >= 1000);
	}

	gro_normal_list(n); // [[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_list().md|gro_normal_list()]]

	/* Some drivers may have called napi_schedule
	 * prior to exhausting their budget.
	 */
	if (unlikely(!list_empty(&n->poll_list))) {
		pr_warn_once("%s: Budget exhausted after napi rescheduled\n",
			     n->dev ? n->dev->name : "backlog");
		return work;
	}

	*repoll = true;

	return work;
}
```

[[Encyclopedia of NetworkSystem/Function/include-linux/napi_complete() .md|napi_complete()]]
[[Encyclopedia of NetworkSystem/Function/include-linux/napi_prefer_busy_poll() .md|napi_prefer_busy_poll()]]
[[Encyclopedia of NetworkSystem/Function/net-core/napi_complete_done().md|napi_complete_done()]]
[[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_list().md|gro_normal_list()]]

> 반드시 NAPI_STATE_SCHED라는 상태여야지만 →poll()을 호출 할 수 있도록 하였다. 이는 netpoll의 poll_napi()와 서로 경쟁하지 않게 하기 위함이다. poll은 napi_struct 구조체의 함수포인터로 실행되게 된다. 이 napi_struct는 softnet_data로부터 비롯되는데, 이는 CPU당 부여되는 구조체이다.
따라서 n→poll()함수를 통해 [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_napi_poll().md|ice_napi_poll]]이 실행되게 된다.
weight은 budget을 의미한다.
