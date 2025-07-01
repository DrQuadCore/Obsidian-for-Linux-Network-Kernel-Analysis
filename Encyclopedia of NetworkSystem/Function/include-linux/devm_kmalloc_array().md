---
Parameter:
  - device
  - size_t
  - gfp_t
Return: void
Location: /include/linux/device.h
---

```c title=devm_kmalloc_array()
static inline void *devm_kmalloc_array(struct device *dev,
				       size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;

	return devm_kmalloc(dev, bytes, flags); // [[Encyclopedia of NetworkSystem/Function/drivers-base/devm_kmalloc().md|devm_kmalloc()]]
}
```

[[Encyclopedia of NetworkSystem/Function/drivers-base/devm_kmalloc().md|devm_kmalloc()]]
