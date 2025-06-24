---
Parameter:
  - xdp_buff
  - ice_tx_ring
  - bool
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_txrx_lib.c
---

```c title=__ice_xmit_xdp_ring()
/**
 * __ice_xmit_xdp_ring - submit frame to XDP ring for transmission
 * @xdp: XDP buffer to be placed onto Tx descriptors
 * @xdp_ring: XDP ring for transmission
 * @frame: whether this comes from .ndo_xdp_xmit()
 */
int __ice_xmit_xdp_ring(struct xdp_buff *xdp, struct ice_tx_ring *xdp_ring,
			bool frame)
{
	struct skb_shared_info *sinfo = NULL;
	u32 size = xdp->data_end - xdp->data;
	struct device *dev = xdp_ring->dev;
	u32 ntu = xdp_ring->next_to_use;
	struct ice_tx_desc *tx_desc;
	struct ice_tx_buf *tx_head;
	struct ice_tx_buf *tx_buf;
	u32 cnt = xdp_ring->count;
	void *data = xdp->data;
	u32 nr_frags = 0;
	u32 free_space;
	u32 frag = 0;

	free_space = ICE_DESC_UNUSED(xdp_ring);
	if (free_space < ICE_RING_QUARTER(xdp_ring))
		free_space += ice_clean_xdp_irq(xdp_ring);

	if (unlikely(!free_space))
		goto busy;

	if (unlikely(xdp_buff_has_frags(xdp))) {
		sinfo = xdp_get_shared_info_from_buff(xdp);
		nr_frags = sinfo->nr_frags;
		if (free_space < nr_frags + 1)
			goto busy;
	}

	tx_desc = ICE_TX_DESC(xdp_ring, ntu);
	tx_head = &xdp_ring->tx_buf[ntu];
	tx_buf = tx_head;

	for (;;) {
		dma_addr_t dma;

		dma = dma_map_single(dev, data, size, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma))
			goto dma_unmap;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buf, len, size);
		dma_unmap_addr_set(tx_buf, dma, dma);

		if (frame) {
			tx_buf->type = ICE_TX_BUF_FRAG;
		} else {
			tx_buf->type = ICE_TX_BUF_XDP_TX;
			tx_buf->raw_buf = data;
		}

		tx_desc->buf_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz = ice_build_ctob(0, 0, size, 0);

		ntu++;
		if (ntu == cnt)
			ntu = 0;

		if (frag == nr_frags)
			break;

		tx_desc = ICE_TX_DESC(xdp_ring, ntu);
		tx_buf = &xdp_ring->tx_buf[ntu];

		data = skb_frag_address(&sinfo->frags[frag]);
		size = skb_frag_size(&sinfo->frags[frag]);
		frag++;
	}

	/* store info about bytecount and frag count in first desc */
	tx_head->bytecount = xdp_get_buff_len(xdp);
	tx_head->nr_frags = nr_frags;

	if (frame) {
		tx_head->type = ICE_TX_BUF_XDP_XMIT;
		tx_head->xdpf = xdp->data_hard_start;
	}

	/* update last descriptor from a frame with EOP */
	tx_desc->cmd_type_offset_bsz |=
		cpu_to_le64(ICE_TX_DESC_CMD_EOP << ICE_TXD_QW1_CMD_S);

	xdp_ring->xdp_tx_active++;
	xdp_ring->next_to_use = ntu;

	return ICE_XDP_TX;

dma_unmap:
	for (;;) {
		tx_buf = &xdp_ring->tx_buf[ntu];
		dma_unmap_page(dev, dma_unmap_addr(tx_buf, dma),
			       dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
		dma_unmap_len_set(tx_buf, len, 0);
		if (tx_buf == tx_head)
			break;

		if (!ntu)
			ntu += cnt;
		ntu--;
	}
	return ICE_XDP_CONSUMED;

busy:
	xdp_ring->ring_stats->tx_stats.tx_busy++;

	return ICE_XDP_CONSUMED;
}
```

> Frame을 XDP ring으로 제출하여 전송을 할수 있도록 한다. ice_run_xdp 자체가 tx든 rx든 통합되어 실행되므로, bottom up path에서는 본 코드는 실행되지 않을 것이라고 생각한다. 여기서부터는 본격적으로 XDP이다.