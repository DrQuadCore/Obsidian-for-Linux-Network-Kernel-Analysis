---
Parameter:
  - device
  - size_t
  - dma_addr_t
  - gfp_t
  - long
Return: void
Location: /kernel/dma/mapping.c
---

```c title=dmam_alloc_attrs()
/**
 * dmam_alloc_attrs - Managed dma_alloc_attrs()
 * @dev: Device to allocate non_coherent memory for
 * @size: Size of allocation
 * @dma_handle: Out argument for allocated DMA handle
 * @gfp: Allocation flags
 * @attrs: Flags in the DMA_ATTR_* namespace.
 *
 * Managed dma_alloc_attrs().  Memory allocated using this function will be
 * automatically released on driver detach.
 *
 * RETURNS:
 * Pointer to allocated memory on success, NULL on failure.
 */
void *dmam_alloc_attrs(struct device *dev, size_t size, dma_addr_t *dma_handle,
		gfp_t gfp, unsigned long attrs)
{
	struct dma_devres *dr;
	void *vaddr;

	dr = devres_alloc(dmam_release, sizeof(*dr), gfp);
	if (!dr)
		return NULL;

	vaddr = dma_alloc_attrs(dev, size, dma_handle, gfp, attrs); // [[Encyclopedia of NetworkSystem/Function/kernel-dma/dma_alloc_attrs().md|dma_alloc_attrs()]]
	if (!vaddr) {
		devres_free(dr);
		return NULL;
	}

	dr->vaddr = vaddr;
	dr->dma_handle = *dma_handle;
	dr->size = size;
	dr->attrs = attrs;

	devres_add(dev, dr);

	return vaddr;
}
EXPORT_SYMBOL(dmam_alloc_attrs);
```

[[Encyclopedia of NetworkSystem/Function/kernel-dma/dma_alloc_attrs().md|dma_alloc_attrs()]]

> vaddr는 dma_handle과 똑같은 physical memory를 가르키는 virtual address가 될 것이다. 쭉 함수들을 따라가다보면, dev→dma_mem을 통해 원래 device가 처음 초기화 될 때 할당받은 dma memory pool에서 필요한 크기만큼의 dma 메모리를 할당 받아 이에 대한 virtual address를 가져오게 되는 것이다. dma_get_device_base로 device가 할당받은 dma 메모리의 base address를 가져오게 되고, 앞서 bitmap을 탐색하여 찾은 새로 할당 할 dma 주소의 offset, 혹은 pageno를 가지고 필요한 dma address를 저장하고, device의 base address에 대응하는 mem→virt_base에서 오프셋을 더하여 해당하는 virtual address를 반환하게 된다