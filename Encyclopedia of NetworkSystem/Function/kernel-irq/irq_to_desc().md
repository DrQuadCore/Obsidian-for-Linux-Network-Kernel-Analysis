---
Parameter:
  - int
Return: irq_desc
Location: /kernel/irq/irqdesc.c
---

```c title=irq_to_desc()
struct irq_desc *irq_to_desc(unsigned int irq)
{
	return (irq < NR_IRQS) ? irq_desc + irq : NULL;
}
EXPORT_SYMBOL(irq_to_desc);
```

irq 번호를 통해 irq_desc 구조체를 반환하는 함수. 좀더 살펴볼 여지가 있음