---
Parameter:
  - ice_rx_ring
  - xdp_buff
Return: sk_buff
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_build_skb()
/**
 * ice_build_skb - Build skb around an existing buffer
 * @rx_ring: Rx descriptor ring to transact packets on
 * @xdp: xdp_buff pointing to the data
 *
 * This function builds an skb around an existing XDP buffer, taking care
 * to set up the skb correctly and avoid any memcpy overhead. Driver has
 * already combined frags (if any) to skb_shared_info.
 */
static struct sk_buff *
ice_build_skb(struct ice_rx_ring *rx_ring, struct xdp_buff *xdp)
{
	u8 metasize = xdp->data - xdp->data_meta;
	struct skb_shared_info *sinfo = NULL;
	unsigned int nr_frags;
	struct sk_buff *skb;

	if (unlikely(xdp_buff_has_frags(xdp))) {
		sinfo = xdp_get_shared_info_from_buff(xdp);
		nr_frags = sinfo->nr_frags;
	}

	/* Prefetch first cache line of first page. If xdp->data_meta
	 * is unused, this points exactly as xdp->data, otherwise we
	 * likely have a consumer accessing first few bytes of meta
	 * data, and then actual data.
	 */
	net_prefetch(xdp->data_meta);
	/* build an skb around the page buffer */
	skb = napi_build_skb(xdp->data_hard_start, xdp->frame_sz); // [[napi_build_skb()]]
	if (unlikely(!skb))
		return NULL;

	/* must to record Rx queue, otherwise OS features such as
	 * symmetric queue won't work
	 */
	skb_record_rx_queue(skb, rx_ring->q_index);

	/* update pointers within the skb to store the data */
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	__skb_put(skb, xdp->data_end - xdp->data); // [[__skb_put()]]
	if (metasize)
		skb_metadata_set(skb, metasize);

	if (unlikely(xdp_buff_has_frags(xdp)))
		xdp_update_skb_shared_info(skb, nr_frags,
					   sinfo->xdp_frags_size,
					   nr_frags * xdp->frame_sz,
					   xdp_buff_is_frag_pfmemalloc(xdp));

	return skb;
}
```

[[napi_build_skb()]]
[[__skb_put()]]

> 존재하는 XDP 버퍼에다가 skb 버퍼를 만드는 함수이다. build를 할 수있는지 위의 flag에 따라 본 함수가 실행되거나 아래의 ice_construct_skb가 실행되게 된다.