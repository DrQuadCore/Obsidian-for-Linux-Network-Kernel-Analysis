---
Parameter:
  - irq_data
  - bool
Return: int
Location: /kernel/irq/irqdomain.c
---

```c title=__irq_domain_activate_irq()
static int __irq_domain_activate_irq(struct irq_data *irqd, bool reserve)
{
	int ret = 0;

	if (irqd && irqd->domain) {
		struct irq_domain *domain = irqd->domain;

		if (irqd->parent_data)
			ret = __irq_domain_activate_irq(irqd->parent_data,
							reserve);
		if (!ret && domain->ops->activate) {
			ret = domain->ops->activate(domain, irqd, reserve);
			/* Rollback in case of error */
			if (ret && irqd->parent_data)
				__irq_domain_deactivate_irq(irqd->parent_data);
		}
	}
	return ret;
}
```

> 재귀적으로 irq_data의 부모 데이터가 있다면 이를 활성화 시킴.