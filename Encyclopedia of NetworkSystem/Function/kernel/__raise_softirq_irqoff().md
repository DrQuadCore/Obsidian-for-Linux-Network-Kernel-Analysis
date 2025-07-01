---
Parameter:
  - int
Return: void
Location: /kernel/softirq.c
---

```c title=__raise_softirq_irqoff()
void __raise_softirq_irqoff(unsigned int nr)
{
	lockdep_assert_irqs_disabled();
	trace_softirq_raise(nr);
	or_softirq_pending(1UL << nr); 
	// 해당하는 softirq interrupt를 비트마스크를 통해 활성화 시키면 해당 인터럽트가  
	// 실행 대기 상태가 되고, 커널이 이를 확인하여 인터럽트를 처리함. 
}
```

```c 
enum
{
	HI_SOFTIRQ=0,
	TIMER_SOFTIRQ,
	NET_TX_SOFTIRQ,
	NET_RX_SOFTIRQ,
	BLOCK_SOFTIRQ,
	IRQ_POLL_SOFTIRQ,
	TASKLET_SOFTIRQ,
	SCHED_SOFTIRQ,
	HRTIMER_SOFTIRQ,
	RCU_SOFTIRQ,    /* Preferable RCU should always be the last softirq */

	NR_SOFTIRQS
};
```

NET_RX_SOFTIRQ는 enum으로, 3이라는 값을 가진다. 참고로 TX는 2이다.
1UL<<3으로, 4번째 비트를 켜게 된다. 이를 통해 CPU가 해당 값을 알아차리고
jiffies를 사용하여 sotfIRQ의 timeout을 구현하게 된다. 이 때 최대 값은 MAX_SOFTIRQ_TIME이며, 이를 더하여 할당된 자원을 알 수 있게 된다.