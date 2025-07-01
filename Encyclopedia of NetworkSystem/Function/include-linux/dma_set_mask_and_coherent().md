---
Parameter:
  - device
  - u64
Return: int
Location: /include/linux/dma-mapping.h
---

```c title=devres_alloc()
static inline int dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	int rc = dma_set_mask(dev, mask);
	if (rc == 0)
		dma_set_coherent_mask(dev, mask);
	return rc;
}
```

dma를 설정함