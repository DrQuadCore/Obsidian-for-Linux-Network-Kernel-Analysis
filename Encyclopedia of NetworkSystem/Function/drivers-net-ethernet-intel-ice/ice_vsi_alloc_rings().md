---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_alloc_rings()
/**
 * ice_vsi_alloc_rings - Allocates Tx and Rx rings for the VSI
 * @vsi: VSI which is having rings allocated
 */
static int ice_vsi_alloc_rings(struct ice_vsi *vsi)
{
	bool dvm_ena = ice_is_dvm_ena(&vsi->back->hw);
	struct ice_pf *pf = vsi->back;
	struct device *dev;
	u16 i;

	dev = ice_pf_to_dev(pf);
	/* Allocate Tx rings */
	ice_for_each_alloc_txq(vsi, i) {
		struct ice_tx_ring *ring;

		/* allocate with kzalloc(), free with kfree_rcu() */
		ring = kzalloc(sizeof(*ring), GFP_KERNEL);

		if (!ring)
			goto err_out;

		ring->q_index = i;
		ring->reg_idx = vsi->txq_map[i];
		ring->vsi = vsi;
		ring->tx_tstamps = &pf->ptp.port.tx;
		ring->dev = dev;
		ring->count = vsi->num_tx_desc;
		ring->txq_teid = ICE_INVAL_TEID;
		if (dvm_ena)
			ring->flags |= ICE_TX_FLAGS_RING_VLAN_L2TAG2;
		else
			ring->flags |= ICE_TX_FLAGS_RING_VLAN_L2TAG1;
		WRITE_ONCE(vsi->tx_rings[i], ring);
	}

	/* Allocate Rx rings */
	ice_for_each_alloc_rxq(vsi, i) {
		struct ice_rx_ring *ring;

		/* allocate with kzalloc(), free with kfree_rcu() */
		ring = kzalloc(sizeof(*ring), GFP_KERNEL);
		if (!ring)
			goto err_out;

		ring->q_index = i;
		ring->reg_idx = vsi->rxq_map[i];
		ring->vsi = vsi;
		ring->netdev = vsi->netdev;
		ring->dev = dev;
		ring->count = vsi->num_rx_desc;
		ring->cached_phctime = pf->ptp.cached_phc_time;
		WRITE_ONCE(vsi->rx_rings[i], ring);
	}

	return 0;

err_out:
	ice_vsi_clear_rings(vsi);
	return -ENOMEM;
}
```

