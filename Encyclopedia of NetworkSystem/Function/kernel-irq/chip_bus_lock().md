---
Parameter:
  - irq_desc
Return: void
Location: /kernel/irq/internals.h
---

```c title=chip_bus_lock()
/* Inline functions for support of irq chips on slow busses */
static inline void chip_bus_lock(struct irq_desc *desc)
{
	if (unlikely(desc->irq_data.chip->irq_bus_lock))
		desc->irq_data.chip->irq_bus_lock(&desc->irq_data);
}
```

irq_bus_lock()의 잘못된 사용을 막기 위한 함수이다.