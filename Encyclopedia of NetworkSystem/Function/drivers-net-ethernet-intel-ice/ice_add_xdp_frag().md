---
Parameter:
  - ice_rx_ring
  - xdp_buff
  - ice_rx_buf
  - int
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_add_xdp_frag()
/**
 * ice_add_xdp_frag - Add contents of Rx buffer to xdp buf as a frag
 * @rx_ring: Rx descriptor ring to transact packets on
 * @xdp: xdp buff to place the data into
 * @rx_buf: buffer containing page to add
 * @size: packet length from rx_desc
 *
 * This function will add the data contained in rx_buf->page to the xdp buf.
 * It will just attach the page as a frag.
 */
static int
ice_add_xdp_frag(struct ice_rx_ring *rx_ring, struct xdp_buff *xdp,
		 struct ice_rx_buf *rx_buf, const unsigned int size)
{
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);

	if (!size)
		return 0;

	if (!xdp_buff_has_frags(xdp)) {
		sinfo->nr_frags = 0;
		sinfo->xdp_frags_size = 0;
		xdp_buff_set_frags_flag(xdp);
	}

	if (unlikely(sinfo->nr_frags == MAX_SKB_FRAGS)) {
		ice_set_rx_bufs_act(xdp, rx_ring, ICE_XDP_CONSUMED);
		return -ENOMEM;
	}

	__skb_fill_page_desc_noacc(sinfo, sinfo->nr_frags++, rx_buf->page,
				   rx_buf->page_offset, size);
	sinfo->xdp_frags_size += size;
	/* remember frag count before XDP prog execution; bpf_xdp_adjust_tail()
	 * can pop off frags but driver has to handle it on its own
	 */
	rx_ring->nr_frags = sinfo->nr_frags;

	if (page_is_pfmemalloc(rx_buf->page))
		xdp_buff_set_frag_pfmemalloc(xdp);

	return 0;
}
```

> xdp buf에다가 frag로써 Rx buffer의 컨텐츠를 추가하게 된다.