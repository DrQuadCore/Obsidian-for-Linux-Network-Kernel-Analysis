---
Parameter:
  - device
  - int
  - irq_handler_t
  - long
  - char
  - void
Return: int
Location: /include/linux/interrupt.h
---

```c title=devm_request_irq()
static inline int __must_check
devm_request_irq(struct device *dev, unsigned int irq, irq_handler_t handler,
		 unsigned long irqflags, const char *devname, void *dev_id)
{
	return devm_request_threaded_irq(dev, irq, handler, NULL, irqflags,
					 devname, dev_id); // [[Encyclopedia of NetworkSystem/Function/kernel-irq/devm_request_threaded_irq().md|devm_request_threaded_irq()]]
}
```

[[Encyclopedia of NetworkSystem/Function/kernel-irq/devm_request_threaded_irq().md|devm_request_threaded_irq()]]
