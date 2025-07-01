---
Parameter:
  - irq_data
Return: void
Location: /include/linux/irq.h
---

```c title=irqd_set_activated()
static inline void irqd_set_activated(struct irq_data *d)
{
	__irqd_to_state(d) |= IRQD_ACTIVATED;
}
```
