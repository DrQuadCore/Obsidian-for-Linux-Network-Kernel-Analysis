---
Parameter:
  - bool
Return: void
Location: /kernel/softirq.c
---

```c title=handle_softirqs()
static void handle_softirqs(bool ksirqd)
{
	unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
	unsigned long old_flags = current->flags;
	int max_restart = MAX_SOFTIRQ_RESTART;
	struct softirq_action *h;
	bool in_hardirq;
	__u32 pending;
	int softirq_bit;

	/*
	 * Mask out PF_MEMALLOC as the current task context is borrowed for the
	 * softirq. A softirq handled, such as network RX, might set PF_MEMALLOC
	 * again if the socket is related to swapping.
	 */
	current->flags &= ~PF_MEMALLOC;

	pending = local_softirq_pending(); //softIRQ에 대한 모든 bitmap을 불러옴

	softirq_handle_begin();
	in_hardirq = lockdep_softirq_start();
	account_softirq_enter(current);

restart:
	/* Reset the pending bitmask before enabling irqs */
	set_softirq_pending(0);

	local_irq_enable();

	h = softirq_vec;

	while ((softirq_bit = ffs(pending))) { //ffs : set 된 것 중 가장 낮은 거리를 찾음.
	// 즉 set된 모든 비트가 0이 될 때까지 아래의 코드를 반복함. 
		unsigned int vec_nr;
		int prev_count;

		h += softirq_bit - 1;

		vec_nr = h - softirq_vec;
		prev_count = preempt_count();

		kstat_incr_softirqs_this_cpu(vec_nr);

		trace_softirq_entry(vec_nr);
		h->action(h); // 실제 softIRQ가 실행되는 부분
		trace_softirq_exit(vec_nr);
		if (unlikely(prev_count != preempt_count())) {
			pr_err("huh, entered softirq %u %s %p with preempt_count %08x, exited with %08x?\n",
			       vec_nr, softirq_to_name[vec_nr], h->action,
			       prev_count, preempt_count());
			preempt_count_set(prev_count);
		}
		h++;
		pending >>= softirq_bit;
	}

	if (!IS_ENABLED(CONFIG_PREEMPT_RT) && ksirqd)
		rcu_softirq_qs();

	local_irq_disable();

	pending = local_softirq_pending();
	if (pending) {
		if (time_before(jiffies, end) && !need_resched() &&
		    --max_restart)
			goto restart;

		wakeup_softirqd();
	}

	account_softirq_exit(current);
	lockdep_softirq_end(in_hardirq);
	softirq_handle_end();
	current_restore_flags(old_flags, PF_MEMALLOC);
}
```

> h→action(h)에서 함수포인터를 통해 미리 매핑되어있던 [[Encyclopedia of NetworkSystem/Function/net-core/net_rx_action().md|net_rx_action]]이 실행되게 됨.