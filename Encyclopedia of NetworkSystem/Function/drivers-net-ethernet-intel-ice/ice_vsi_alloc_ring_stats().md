---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_alloc_ring_stats()
/**
 * ice_vsi_alloc_ring_stats - Allocates Tx and Rx ring stats for the VSI
 * @vsi: VSI which is having stats allocated
 */
static int ice_vsi_alloc_ring_stats(struct ice_vsi *vsi)
{
	struct ice_ring_stats **tx_ring_stats;
	struct ice_ring_stats **rx_ring_stats;
	struct ice_vsi_stats *vsi_stats;
	struct ice_pf *pf = vsi->back;
	u16 i;

	vsi_stats = pf->vsi_stats[vsi->idx];
	tx_ring_stats = vsi_stats->tx_ring_stats;
	rx_ring_stats = vsi_stats->rx_ring_stats;

	/* Allocate Tx ring stats */
	ice_for_each_alloc_txq(vsi, i) {
		struct ice_ring_stats *ring_stats;
		struct ice_tx_ring *ring;

		ring = vsi->tx_rings[i];
		ring_stats = tx_ring_stats[i];

		if (!ring_stats) {
			ring_stats = kzalloc(sizeof(*ring_stats), GFP_KERNEL);
			if (!ring_stats)
				goto err_out;

			WRITE_ONCE(tx_ring_stats[i], ring_stats);
		}

		ring->ring_stats = ring_stats;
	}

	/* Allocate Rx ring stats */
	ice_for_each_alloc_rxq(vsi, i) {
		struct ice_ring_stats *ring_stats;
		struct ice_rx_ring *ring;

		ring = vsi->rx_rings[i];
		ring_stats = rx_ring_stats[i];

		if (!ring_stats) {
			ring_stats = kzalloc(sizeof(*ring_stats), GFP_KERNEL);
			if (!ring_stats)
				goto err_out;

			WRITE_ONCE(rx_ring_stats[i], ring_stats);
		}

		ring->ring_stats = ring_stats;
	}

	return 0;

err_out:
	ice_vsi_free_stats(vsi);
	return -ENOMEM;
}
```

