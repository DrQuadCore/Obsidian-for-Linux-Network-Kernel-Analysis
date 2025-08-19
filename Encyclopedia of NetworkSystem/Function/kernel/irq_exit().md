---
Parameter:
  - void
Return: void
Location: /kernel/softirq.c
---
```c title=irq_exit()
/**
 * irq_exit - Exit an interrupt context, update RCU and lockdep
 *
 * Also processes softirqs if needed and possible.
 */
void irq_exit(void)
{
	__irq_exit_rcu(); //[[__irq_exit_rcu()]]
	ct_irq_exit();
	 /* must be last! */
	lockdep_hardirq_exit();
} 
```