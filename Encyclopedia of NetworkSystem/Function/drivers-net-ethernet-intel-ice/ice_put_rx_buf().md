---
Parameter:
  - ice_rx_ring
  - ice_rx_buf
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_put_rx_buf()
/**
 * ice_put_rx_buf - Clean up used buffer and either recycle or free
 * @rx_ring: Rx descriptor ring to transact packets on
 * @rx_buf: Rx buffer to pull data from
 *
 * This function will clean up the contents of the rx_buf. It will either
 * recycle the buffer or unmap it and free the associated resources.
 */
static void
ice_put_rx_buf(struct ice_rx_ring *rx_ring, struct ice_rx_buf *rx_buf)
{
	if (!rx_buf)
		return;

	if (ice_can_reuse_rx_page(rx_buf)) {
		/* hand second half of page back to the ring */
		ice_reuse_rx_page(rx_ring, rx_buf);
	} else {
		/* we are not reusing the buffer so unmap it */
		dma_unmap_page_attrs(rx_ring->dev, rx_buf->dma,
				     ice_rx_pg_size(rx_ring), DMA_FROM_DEVICE,
				     ICE_RX_DMA_ATTR);
		__page_frag_cache_drain(rx_buf->page, rx_buf->pagecnt_bias);
	}

	/* clear contents of buffer_info */
	rx_buf->page = NULL;
}
```

> napi를 통해 skb로 올라간 뒤, 다 쓰여진 버퍼를 재활용하거나 아니면 할당 해제 해주는 함수. 만약 재사용이 가능하다면 ice_reuse_rx_page(rx_ring, rx_buf)를 통하여 사용하게 된다. 아니라면, dma_unmap_page_attrs를 통해 unmap을 하게 된다.
