---
Parameter:
  - ice_tx_ring
Return: bool
Location: /drivers/net/ethernet/intel/ice/ice_xsk.c
---

```c title=ice_xmit_zc()
/**
 * ice_xmit_zc - take entries from XSK Tx ring and place them onto HW Tx ring
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 *
 * Returns true if there is no more work that needs to be done, false otherwise
 */
bool ice_xmit_zc(struct ice_tx_ring *xdp_ring)
{
	struct xdp_desc *descs = xdp_ring->xsk_pool->tx_descs;
	u32 nb_pkts, nb_processed = 0;
	unsigned int total_bytes = 0;
	int budget;

	ice_clean_xdp_irq_zc(xdp_ring);

	budget = ICE_DESC_UNUSED(xdp_ring);
	budget = min_t(u16, budget, ICE_RING_QUARTER(xdp_ring));

	nb_pkts = xsk_tx_peek_release_desc_batch(xdp_ring->xsk_pool, budget);
	if (!nb_pkts)
		return true;

	if (xdp_ring->next_to_use + nb_pkts >= xdp_ring->count) {
		nb_processed = xdp_ring->count - xdp_ring->next_to_use;
		ice_fill_tx_hw_ring(xdp_ring, descs, nb_processed, &total_bytes);
		xdp_ring->next_to_use = 0;
	}

	ice_fill_tx_hw_ring(xdp_ring, &descs[nb_processed], nb_pkts - nb_processed,
			    &total_bytes);

	ice_set_rs_bit(xdp_ring);
	ice_xdp_ring_update_tail(xdp_ring);
	ice_update_tx_ring_stats(xdp_ring, nb_pkts, total_bytes);

	if (xsk_uses_need_wakeup(xdp_ring->xsk_pool))
		xsk_set_tx_need_wakeup(xdp_ring->xsk_pool);

	return nb_pkts < budget;
}
```
