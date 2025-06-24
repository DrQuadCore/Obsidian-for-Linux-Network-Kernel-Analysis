---
Parameter:
  - irqaction
  - int
  - bool
Return: int
Location: /kernel/irq/manage.c
---

```c title=setup_irq_thread()
static int
setup_irq_thread(struct irqaction *new, unsigned int irq, bool secondary)
{
	struct task_struct *t;

	if (!secondary) {
		t = kthread_create(irq_thread, new, "irq/%d-%s", irq,
				   new->name); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_thread().md|irq_thread()]]
	} else {
		t = kthread_create(irq_thread, new, "irq/%d-s-%s", irq,
				   new->name); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_thread().md|irq_thread()]]
	}

	if (IS_ERR(t))
		return PTR_ERR(t);

	/*
	 * We keep the reference to the task struct even if
	 * the thread dies to avoid that the interrupt code
	 * references an already freed task_struct.
	 */
	new->thread = get_task_struct(t);
	/*
	 * Tell the thread to set its affinity. This is
	 * important for shared interrupt handlers as we do
	 * not invoke setup_affinity() for the secondary
	 * handlers as everything is already set up. Even for
	 * interrupts marked with IRQF_NO_BALANCE this is
	 * correct as we want the thread to move to the cpu(s)
	 * on which the requesting code placed the interrupt.
	 */
	set_bit(IRQTF_AFFINITY, &new->thread_flags);
	return 0;
}
```

[[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_thread().md|irq_thread()]]

`*data`로 들어온 irqaction 에 해당하는 irq_handler 함수를 처리하기 위한 커널 쓰레드를 생성하는 함수이다. 해당하는 irq_handler를 실행하는게 아닌 irq_thread()라는 함수를 실행함, 프로세스 이름은 “irq/{irq number}-{irq action의 이름}”으로 지정됨.