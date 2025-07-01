---
Parameter:
  - irq_desc
  - bool
Return: int
Location: /kernel/irq/chip.c
---

```c title=irq_startup()
int irq_startup(struct irq_desc *desc, bool resend, bool force)
{
	struct irq_data *d = irq_desc_get_irq_data(desc);
	const struct cpumask *aff = irq_data_get_affinity_mask(d);
	int ret = 0;

	desc->depth = 0;

	if (irqd_is_started(d)) {
		irq_enable(desc);
	} else {
		switch (__irq_startup_managed(desc, aff, force)) {
		case IRQ_STARTUP_NORMAL:
			if (d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP)
				irq_setup_affinity(desc);
			ret = __irq_startup(desc);
			if (!(d->chip->flags & IRQCHIP_AFFINITY_PRE_STARTUP))
				irq_setup_affinity(desc);
			break;
		case IRQ_STARTUP_MANAGED:
			irq_do_set_affinity(d, aff, false);
			ret = __irq_startup(desc);
			break;
		case IRQ_STARTUP_ABORT:
			irqd_set_managed_shutdown(d);
			return 0;
		}
	}
	if (resend)
		check_irq_resend(desc, false);

	return ret;
}
```

