---
Parameter:
  - napi_struct
Return: void
Location: /net/core/dev.c
---

```c title=__napi_schedule()
void __napi_schedule(struct napi_struct *n)
{
	unsigned long flags;

	local_irq_save(flags);
	____napi_schedule(this_cpu_ptr(&softnet_data), n); // [[Encyclopedia of NetworkSystem/Function/net-core/____napi_schedule().md|__napi_schedule()]]
	local_irq_restore(flags);
}
EXPORT_SYMBOL(__napi_schedule);
```

[[Encyclopedia of NetworkSystem/Function/net-core/____napi_schedule().md|__napi_schedule()]]
