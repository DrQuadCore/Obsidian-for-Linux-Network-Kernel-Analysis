---
Parameter:
  - napi_struct
  - softnet_data
Return:
  - void
Location: /net/core/dev.c
---

```c title=____napi_schedule()
static inline void ____napi_schedule(struct softnet_data *sd,
				     struct napi_struct *napi)
{
	struct task_struct *thread;

	lockdep_assert_irqs_disabled();

	if (test_bit(NAPI_STATE_THREADED, &napi->state)) {
		/* Paired with smp_mb__before_atomic() in
		 * napi_enable()/dev_set_threaded().
		 * Use READ_ONCE() to guarantee a complete
		 * read on napi->thread. Only call
		 * wake_up_process() when it's not NULL.
		 */
		thread = READ_ONCE(napi->thread);
		if (thread) {
			/* Avoid doing set_bit() if the thread is in
			 * INTERRUPTIBLE state, cause napi_thread_wait()
			 * makes sure to proceed with napi polling
			 * if the thread is explicitly woken from here.
			 */
			if (READ_ONCE(thread->__state) != TASK_INTERRUPTIBLE)
				set_bit(NAPI_STATE_SCHED_THREADED, &napi->state);
			wake_up_process(thread);
			return;
		}
	}

	list_add_tail(&napi->poll_list, &sd->poll_list); // [[Encyclopedia of NetworkSystem/Function/include-linux/list_add_tail().md|list_add_tail()]]
	WRITE_ONCE(napi->list_owner, smp_processor_id());
	/* If not called from net_rx_action()
	 * we have to raise NET_RX_SOFTIRQ.
	 */
	if (!sd->in_net_rx_action)
		__raise_softirq_irqoff(NET_RX_SOFTIRQ); // [[Encyclopedia of NetworkSystem/Function/kernel/__raise_softirq_irqoff().md|__raise_softirq_irqoff()]]
}
```

[[Encyclopedia of NetworkSystem/Function/include-linux/list_add_tail().md|list_add_tail()]]
[[Encyclopedia of NetworkSystem/Function/kernel/__raise_softirq_irqoff().md|__raise_softirq_irqoff()]]

쓰레드를 새로 만들어서 napi→thread 멤버를 불러와 해당 프로세스를 실행하게 됨. task_struct는 include/linux/sched.h에 있음.

1. `lockdep_assert_irqs_disabled()` : NAPI 이후에는 irq 금지
2. NAPI의 상태가 thread이면서, NAPI의 thread가 존재할 경우 진행
    1. 이 함수에서만 napi polling이 깨워지기 위해서 한다고함
    2. napi_thread_wait() 이 다른곳에서 깨워지는 것을 막는다
3. NAPI의 thread가 interruptable이 아닌 경우
    1. NAPI를 실행한다. poll을 schedule 상태로 바꾼다
    2. poll list는 NAPI_STATE_SCHED bit를 관리하는 존재에 의해서만 관리
    3. bit를 킨 존재는, bit를 끌 수도 있다.