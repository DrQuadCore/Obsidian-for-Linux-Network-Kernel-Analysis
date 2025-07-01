---
Parameter:
  - device
  - size_t
  - gfp_t
Return: void
Location: /include/linux/device.h
---

```c title=devm_kcalloc()
static inline void *devm_kcalloc(struct device *dev,
				 size_t n, size_t size, gfp_t flags)
{
	return devm_kmalloc_array(dev, n, size, flags | __GFP_ZERO); // [[Encyclopedia of NetworkSystem/Function/include-linux/devm_kmalloc_array().md|devm_kmalloc_array()]]
}
```

[[Encyclopedia of NetworkSystem/Function/include-linux/devm_kmalloc_array().md|devm_kmalloc_array()]]
