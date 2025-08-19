---
Parameter:
  - void
Return: void
Location: /kernel/softirq.c
---
```c title=__irq_exit_rcu()
static inline void __irq_exit_rcu(void)
{
#ifndef __ARCH_IRQ_EXIT_IRQS_DISABLED
	local_irq_disable();
#else
	lockdep_assert_irqs_disabled();
#endif
	account_hardirq_exit(current);
	preempt_count_sub(HARDIRQ_OFFSET);
	if (!in_interrupt() && local_softirq_pending()) 
		invoke_softirq(); // 여기서 pending 된 softirq invoke

	tick_irq_exit();
}
```