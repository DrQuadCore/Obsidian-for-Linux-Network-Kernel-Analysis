---
Parameter:
  - irq_desc
Return: int
Location: /kernel/irq/chip.c
---

```c title=irq_activate()
int irq_activate(struct irq_desc *desc)
{
	struct irq_data *d = irq_desc_get_irq_data(desc);

	if (!irqd_affinity_is_managed(d))
		return irq_domain_activate_irq(d, false); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_domain_activate_irq().md|irq_domain_activate_irq()]]
	return 0;
}
```

[[Encyclopedia of NetworkSystem/Function/kernel-irq/irq_domain_activate_irq().md|irq_domain_activate_irq()]]

