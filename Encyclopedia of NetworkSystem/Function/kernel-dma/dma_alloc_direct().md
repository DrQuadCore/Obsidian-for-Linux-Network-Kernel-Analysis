---
Parameter:
  - device
  - dma_map_ops
Return: bool
Location: /kernel/dma/mapping.c
---

```c title=dma_alloc_direct()

/*
 * Check if the devices uses a direct mapping for streaming DMA operations.
 * This allows IOMMU drivers to set a bypass mode if the DMA mask is large
 * enough.
 */
static inline bool dma_alloc_direct(struct device *dev,
		const struct dma_map_ops *ops)
{
	return dma_go_direct(dev, dev->coherent_dma_mask, ops);
}
```

> dma_alloc_direct()를 통해 device가 direct allocating이 가능하면 IOMMU를 bypass로 하고 해당하는 작업을 수행. 아니라면, ops→alloc 함수를 통해 allocation 수행.