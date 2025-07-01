---
Parameter:
  - ice_rx_ring
  - xdp_buff
Return: sk_buff
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_construct_skb()
/**
 * ice_construct_skb - Allocate skb and populate it
 * @rx_ring: Rx descriptor ring to transact packets on
 * @xdp: xdp_buff pointing to the data
 *
 * This function allocates an skb. It then populates it with the page
 * data from the current receive descriptor, taking care to set up the
 * skb correctly.
 */
static struct sk_buff *
ice_construct_skb(struct ice_rx_ring *rx_ring, struct xdp_buff *xdp)
{
	unsigned int size = xdp->data_end - xdp->data;
	struct skb_shared_info *sinfo = NULL;
	struct ice_rx_buf *rx_buf;
	unsigned int nr_frags = 0;
	unsigned int headlen;
	struct sk_buff *skb;

	/* prefetch first cache line of first page */
	net_prefetch(xdp->data);

	if (unlikely(xdp_buff_has_frags(xdp))) {
		sinfo = xdp_get_shared_info_from_buff(xdp);
		nr_frags = sinfo->nr_frags;
	}

	/* allocate a skb to store the frags */
	skb = __napi_alloc_skb(&rx_ring->q_vector->napi, ICE_RX_HDR_SIZE,
			       GFP_ATOMIC | __GFP_NOWARN); // [[__napi_alloc_skb()]]
	if (unlikely(!skb))
		return NULL;

	rx_buf = &rx_ring->rx_buf[rx_ring->first_desc];
	skb_record_rx_queue(skb, rx_ring->q_index); // [[skb_record_rx_queue()]]
	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > ICE_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, xdp->data, ICE_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), xdp->data, ALIGN(headlen,
							 sizeof(long)));

	/* if we exhaust the linear part then add what is left as a frag */
	size -= headlen;
	if (size) {
		/* besides adding here a partial frag, we are going to add
		 * frags from xdp_buff, make sure there is enough space for
		 * them
		 */
		if (unlikely(nr_frags >= MAX_SKB_FRAGS - 1)) {
			dev_kfree_skb(skb);
			return NULL;
		}
		skb_add_rx_frag(skb, 0, rx_buf->page,
				rx_buf->page_offset + headlen, size,
				xdp->frame_sz);
	} else {
		/* buffer is unused, change the act that should be taken later
		 * on; data was copied onto skb's linear part so there's no
		 * need for adjusting page offset and we can reuse this buffer
		 * as-is
		 */
		rx_buf->act = ICE_SKB_CONSUMED;
	}

	if (unlikely(xdp_buff_has_frags(xdp))) {
		struct skb_shared_info *skinfo = skb_shinfo(skb);

		memcpy(&skinfo->frags[skinfo->nr_frags], &sinfo->frags[0],
		       sizeof(skb_frag_t) * nr_frags);

		xdp_update_skb_shared_info(skb, skinfo->nr_frags + nr_frags,
					   sinfo->xdp_frags_size,
					   nr_frags * xdp->frame_sz,
					   xdp_buff_is_frag_pfmemalloc(xdp));
	}

	return skb;
}
```

[[__napi_alloc_skb()]]  
[[skb_record_rx_queue()]]

> 첫 번째 차이점은 napi_build_skb vs `__napi_alloc_skb` 실행이다. 이후 skb_record_rx_queue를 실행하게 된다.