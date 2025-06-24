---
Parameter:
  - ice_tx_ring
  - int
  - u32
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx_lib.c
---

```c title=ice_finalize_xdp_rx()
/**
 * ice_finalize_xdp_rx - Bump XDP Tx tail and/or flush redirect map
 * @xdp_ring: XDP ring
 * @xdp_res: Result of the receive batch
 * @first_idx: index to write from caller
 *
 * This function bumps XDP Tx tail and/or flush redirect map, and
 * should be called when a batch of packets has been processed in the
 * napi loop.
 */
void ice_finalize_xdp_rx(struct ice_tx_ring *xdp_ring, unsigned int xdp_res,
			 u32 first_idx)
{
	struct ice_tx_buf *tx_buf = &xdp_ring->tx_buf[first_idx];

	if (xdp_res & ICE_XDP_REDIR)
		xdp_do_flush();

	if (xdp_res & ICE_XDP_TX) {
		if (static_branch_unlikely(&ice_xdp_locking_key))
			spin_lock(&xdp_ring->tx_lock);
		/* store index of descriptor with RS bit set in the first
		 * ice_tx_buf of given NAPI batch
		 */
		tx_buf->rs_idx = ice_set_rs_bit(xdp_ring);
		ice_xdp_ring_update_tail(xdp_ring);
		if (static_branch_unlikely(&ice_xdp_locking_key))
			spin_unlock(&xdp_ring->tx_lock);
	}
}
```

> Tx일 때만 사용되므로 집중해서 볼 필요는 없다.