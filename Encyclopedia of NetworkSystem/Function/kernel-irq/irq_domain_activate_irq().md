---
Parameter:
  - irq_data
  - bool
Return: int
Location: /kernel/irq/irqdomain.c
---

```c title=irq_domain_activate_irq()
/**
 * irq_domain_activate_irq - Call domain_ops->activate recursively to activate
 *			     interrupt
 * @irq_data:	Outermost irq_data associated with interrupt
 * @reserve:	If set only reserve an interrupt vector instead of assigning one
 *
 * This is the second step to call domain_ops->activate to program interrupt
 * controllers, so the interrupt could actually get delivered.
 */
int irq_domain_activate_irq(struct irq_data *irq_data, bool reserve)
{
	int ret = 0;

	if (!irqd_is_activated(irq_data))
		ret = __irq_domain_activate_irq(irq_data, reserve); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/__irq_domain_activate_irq().md|__irq_domain_activate_irq()]]
	if (!ret)
		irqd_set_activated(irq_data); // [[Encyclopedia of NetworkSystem/Function/include-linux/irqd_set_activated().md|irqd_set_activated()]]
	return ret;
}
```

[[Encyclopedia of NetworkSystem/Function/kernel-irq/__irq_domain_activate_irq().md|__irq_domain_activate_irq()]]
[[Encyclopedia of NetworkSystem/Function/include-linux/irqd_set_activated().md|irqd_set_activated()]]

