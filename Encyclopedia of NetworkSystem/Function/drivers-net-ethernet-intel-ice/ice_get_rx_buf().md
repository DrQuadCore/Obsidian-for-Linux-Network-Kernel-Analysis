---
Parameter:
  - ice_rx_ring
  - int
Return: ice_rx_buf
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_get_rx_buf()
/**
 * ice_get_rx_buf - Fetch Rx buffer and synchronize data for use
 * @rx_ring: Rx descriptor ring to transact packets on
 * @size: size of buffer to add to skb
 * @ntc: index of next to clean element
 *
 * This function will pull an Rx buffer from the ring and synchronize it
 * for use by the CPU.
 */
static struct ice_rx_buf *
ice_get_rx_buf(struct ice_rx_ring *rx_ring, const unsigned int size,
	       const unsigned int ntc)
{
	struct ice_rx_buf *rx_buf;

	rx_buf = &rx_ring->rx_buf[ntc];
	rx_buf->pgcnt =
#if (PAGE_SIZE < 8192)
		page_count(rx_buf->page);
#else
		0;
#endif
	prefetchw(rx_buf->page);

	if (!size)
		return rx_buf;
	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev, rx_buf->dma,
				      rx_buf->page_offset, size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	rx_buf->pagecnt_bias--;

	return rx_buf;
}
```

> Rx Buffer를 사용하기 위해 가져와서 동기화시키는 함수이다. prefetchw(rx_buf→page)함수를 사용한다. 그후 dma_sync_single_range_for_cpu() 함수를 통해 싱크를 진행한다.