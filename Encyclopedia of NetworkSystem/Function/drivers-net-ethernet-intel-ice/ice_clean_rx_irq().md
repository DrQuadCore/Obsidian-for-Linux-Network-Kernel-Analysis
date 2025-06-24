---
Parameter:
  - ice_rx_ring
  - int
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_clean_rx_irq()
/**
 * ice_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @rx_ring: Rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing. The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 */
int ice_clean_rx_irq(struct ice_rx_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_pkts = 0;
	unsigned int offset = rx_ring->rx_offset;
	struct xdp_buff *xdp = &rx_ring->xdp;
	u32 cached_ntc = rx_ring->first_desc;
	struct ice_tx_ring *xdp_ring = NULL;
	struct bpf_prog *xdp_prog = NULL;
	u32 ntc = rx_ring->next_to_clean;
	u32 cnt = rx_ring->count;
	u32 xdp_xmit = 0;
	u32 cached_ntu;
	bool failure;
	u32 first;

	/* Frame size depend on rx_ring setup when PAGE_SIZE=4K */
#if (PAGE_SIZE < 8192)
	xdp->frame_sz = ice_rx_frame_truesize(rx_ring, 0);
#endif

	xdp_prog = READ_ONCE(rx_ring->xdp_prog);
	if (xdp_prog) {
		xdp_ring = rx_ring->xdp_ring;
		cached_ntu = xdp_ring->next_to_use;
	}

	/* start the loop to process Rx packets bounded by 'budget' */
	while (likely(total_rx_pkts < (unsigned int)budget)) {
		union ice_32b_rx_flex_desc *rx_desc;
		struct ice_rx_buf *rx_buf;
		struct sk_buff *skb;
		unsigned int size;
		u16 stat_err_bits;
		u16 vlan_tci;

		/* get the Rx desc from Rx ring based on 'next_to_clean' */
		rx_desc = ICE_RX_DESC(rx_ring, ntc);

		/* status_error_len will always be zero for unused descriptors
		 * because it's cleared in cleanup, and overlaps with hdr_addr
		 * which is always zero because packet split isn't used, if the
		 * hardware wrote DD then it will be non-zero
		 */
		stat_err_bits = BIT(ICE_RX_FLEX_DESC_STATUS0_DD_S);
		if (!ice_test_staterr(rx_desc->wb.status_error0, stat_err_bits))
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * DD bit is set.
		 */
		dma_rmb();

		ice_trace(clean_rx_irq, rx_ring, rx_desc);
		if (rx_desc->wb.rxdid == FDIR_DESC_RXDID || !rx_ring->netdev) {
			struct ice_vsi *ctrl_vsi = rx_ring->vsi;

			if (rx_desc->wb.rxdid == FDIR_DESC_RXDID &&
			    ctrl_vsi->vf)
				ice_vc_fdir_irq_handler(ctrl_vsi, rx_desc);
			if (++ntc == cnt)
				ntc = 0;
			rx_ring->first_desc = ntc;
			continue;
		}

		size = le16_to_cpu(rx_desc->wb.pkt_len) &
			ICE_RX_FLX_DESC_PKT_LEN_M;

		/* retrieve a buffer from the ring */
		rx_buf = ice_get_rx_buf(rx_ring, size, ntc); // [[ice_get_rx_buf()]]

		if (!xdp->data) {
			void *hard_start;

			hard_start = page_address(rx_buf->page) + rx_buf->page_offset -
				     offset;
			xdp_prepare_buff(xdp, hard_start, offset, size, !!offset); // [[xdp_prepare_buff()]]
#if (PAGE_SIZE > 4096)
			/* At larger PAGE_SIZE, frame_sz depend on len size */
			xdp->frame_sz = ice_rx_frame_truesize(rx_ring, size);
#endif
			xdp_buff_clear_frags_flag(xdp);
		} else if (ice_add_xdp_frag(rx_ring, xdp, rx_buf, size)) { // [[ice_add_xdp_frag()]]
			break;
		}
		if (++ntc == cnt)
			ntc = 0;

		/* skip if it is NOP desc */
		if (ice_is_non_eop(rx_ring, rx_desc))
			continue;

		ice_run_xdp(rx_ring, xdp, xdp_prog, xdp_ring, rx_buf, rx_desc); // [[ice_run_xdp()]]
		if (rx_buf->act == ICE_XDP_PASS)
			goto construct_skb;
		total_rx_bytes += xdp_get_buff_len(xdp);
		total_rx_pkts++;

		xdp->data = NULL;
		rx_ring->first_desc = ntc;
		rx_ring->nr_frags = 0;
		continue;
construct_skb:
		if (likely(ice_ring_uses_build_skb(rx_ring))) // [[ice_ring_uses_build_skb()]]
			skb = ice_build_skb(rx_ring, xdp); // [[ice_build_skb()]]
		else
			skb = ice_construct_skb(rx_ring, xdp); // [[ice_construct_skb()]]
		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->ring_stats->rx_stats.alloc_page_failed++;
			rx_buf->act = ICE_XDP_CONSUMED;
			if (unlikely(xdp_buff_has_frags(xdp)))
				ice_set_rx_bufs_act(xdp, rx_ring,
						    ICE_XDP_CONSUMED);
			xdp->data = NULL;
			rx_ring->first_desc = ntc;
			rx_ring->nr_frags = 0;
			break;
		}
		xdp->data = NULL;
		rx_ring->first_desc = ntc;
		rx_ring->nr_frags = 0;

		stat_err_bits = BIT(ICE_RX_FLEX_DESC_STATUS0_RXE_S);
		if (unlikely(ice_test_staterr(rx_desc->wb.status_error0,
					      stat_err_bits))) {
			dev_kfree_skb_any(skb);
			continue;
		}

		vlan_tci = ice_get_vlan_tci(rx_desc);

		/* pad the skb if needed, to make a valid ethernet frame */
		if (eth_skb_pad(skb))
			continue;

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* populate checksum, VLAN, and protocol */
		ice_process_skb_fields(rx_ring, rx_desc, skb); // [[ice_process_skb_fields()]]

		ice_trace(clean_rx_irq_indicate, rx_ring, rx_desc, skb);
		/* send completed skb up the stack */
		ice_receive_skb(rx_ring, skb, vlan_tci); // [[ice_receive_skb()]]

		/* update budget accounting */
		total_rx_pkts++;
	}

	first = rx_ring->first_desc;
	while (cached_ntc != first) {
		struct ice_rx_buf *buf = &rx_ring->rx_buf[cached_ntc];

		if (buf->act & (ICE_XDP_TX | ICE_XDP_REDIR)) {
			ice_rx_buf_adjust_pg_offset(buf, xdp->frame_sz);
			xdp_xmit |= buf->act;
		} else if (buf->act & ICE_XDP_CONSUMED) {
			buf->pagecnt_bias++;
		} else if (buf->act == ICE_XDP_PASS) {
			ice_rx_buf_adjust_pg_offset(buf, xdp->frame_sz);
		}

		ice_put_rx_buf(rx_ring, buf); // [[ice_put_rx_buf()]]
		if (++cached_ntc >= cnt)
			cached_ntc = 0;
	}
	rx_ring->next_to_clean = ntc;
	/* return up to cleaned_count buffers to hardware */
	failure = ice_alloc_rx_bufs(rx_ring, ICE_RX_DESC_UNUSED(rx_ring)); // [[ice_alloc_rx_bufs()]]

	if (xdp_xmit)
		ice_finalize_xdp_rx(xdp_ring, xdp_xmit, cached_ntu); // [[ice_finalize_xdp_rx()]]

	if (rx_ring->ring_stats)
		ice_update_rx_ring_stats(rx_ring, total_rx_pkts,
					 total_rx_bytes); // [[ice_update_rx_ring_stats()]]

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_pkts;
}
```

[[ice_get_rx_buf()]]
[[xdp_prepare_buff()]]
[[ice_add_xdp_frag()]]
[[ice_run_xdp()]]
[[ice_ring_uses_build_skb()]]
[[ice_build_skb()]]
[[ice_construct_skb()]]
[[ice_process_skb_fields()]]
[[ice_receive_skb()]]
[[ice_put_rx_buf()]]
[[ice_alloc_rx_bufs()]]
[[ice_finalize_xdp_rx()]]
[[ice_update_rx_ring_stats()]]

> xdp를 무조건 셋팅하는 것으로 보인다. 우선 없다고 가정하고 보면 if(!xdp→data)를 통해 확인하여 ice_add_xdp_frag() 함수를 실행할 것이다. 그러고 나서 ice_run_xdp()를 실행한다. 이후에 보면 construct_skb:라는 label이 존재한다. 이는 네트워크 스택에 링버퍼의 내용을 전달하는 뜻으로, ICE_XDP_PASS값을 rx_buf→act에서 가질 때 실행되게 된다. 그게 아니라면 중간의 continue; 때문에 construct_skb: 라벨 아래의 코드들은 실행되지 않게 된다. construct_skb: 라벨 아래에서는 전통적인 네트워크 스택이 진행되게 된다.
>
>중간에 ICE_RX_DESC() 매크로를 통하여 rx_ring의 ntc 인덱스에 있는 desc를 해당하는 구조체 타입으로 캐스팅하여 가져오게 된다.
>
>또한 만약 xdp->data가 null값이라면, 즉 xdp가 가르키고 있는 data 영역이 존재하지 않는다면, 직접 rx_buf-> page로 접근하여 해당 page_address를 hard_start로 하여 data 영역의 head 부분을 가르키게 한다. 이후 xdp_prepare_buff 함수를 호출하여 xdp_buff를 사용할 수 있도록 설정한다.
>
>budget을 다 사용하였을 경우 while문을 빠져나오게 되는데, 여기는 gro를 통해 전부 끝났을 경우이다.