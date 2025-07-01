---
Parameter:
  - void
Return: int
Location: /kernel/irq/manage.c
---

```c title=irq_thread()
/*
 * Interrupt handler thread
 */
static int irq_thread(void *data)
{
	struct callback_head on_exit_work;
	struct irqaction *action = data;
	struct irq_desc *desc = irq_to_desc(action->irq);
	irqreturn_t (*handler_fn)(struct irq_desc *desc,
			struct irqaction *action);

	irq_thread_set_ready(desc, action);

	sched_set_fifo(current);

	if (force_irqthreads() && test_bit(IRQTF_FORCED_THREAD,
					   &action->thread_flags))
		handler_fn = irq_forced_thread_fn;
	else
		handler_fn = irq_thread_fn;

	init_task_work(&on_exit_work, irq_thread_dtor);
	task_work_add(current, &on_exit_work, TWA_NONE);

	while (!irq_wait_for_interrupt(desc, action)) {
		irqreturn_t action_ret;

		action_ret = handler_fn(desc, action);
		if (action_ret == IRQ_WAKE_THREAD)
			irq_wake_secondary(desc, action);

		wake_threads_waitq(desc);
	}

	/*
	 * This is the regular exit path. __free_irq() is stopping the
	 * thread via kthread_stop() after calling
	 * synchronize_hardirq(). So neither IRQTF_RUNTHREAD nor the
	 * oneshot mask bit can be set.
	 */
	task_work_cancel(current, irq_thread_dtor);
	return 0;
}
```

Interrupt handler thread라고 주석 되어 있음. handler_fn 함수 포인터를 선언하여 기다리고 있다가 만약 하드웨어 인터럽트가 끝났다면 irq_thread_fn을 실행함. 이때, irq_thread_fn() 함수는 thread_fn을 실행하게 됨. 여기서부터 software interrupt 처리 과정이 됨.