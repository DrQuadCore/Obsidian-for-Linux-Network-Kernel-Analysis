---
Parameter:
  - irq_data
  - int
Return: void
Location: /kernel/irq/internals.h
---

```c title=irqd_set()
static inline void irqd_set(struct irq_data *d, unsigned int mask)
{
	__irqd_to_state(d) |= mask;
}
```

