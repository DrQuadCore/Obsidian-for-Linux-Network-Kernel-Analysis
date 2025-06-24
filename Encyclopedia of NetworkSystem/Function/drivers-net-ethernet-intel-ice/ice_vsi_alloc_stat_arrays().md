---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_alloc_stat_arrays()
/**
 * ice_vsi_alloc_stat_arrays - Allocate statistics arrays
 * @vsi: VSI pointer
 */
static int ice_vsi_alloc_stat_arrays(struct ice_vsi *vsi)
{
	struct ice_vsi_stats *vsi_stat;
	struct ice_pf *pf = vsi->back;

	if (vsi->type == ICE_VSI_CHNL)
		return 0;
	if (!pf->vsi_stats)
		return -ENOENT;

	if (pf->vsi_stats[vsi->idx])
	/* realloc will happen in rebuild path */
		return 0;

	vsi_stat = kzalloc(sizeof(*vsi_stat), GFP_KERNEL);
	if (!vsi_stat)
		return -ENOMEM;

	vsi_stat->tx_ring_stats =
		kcalloc(vsi->alloc_txq, sizeof(*vsi_stat->tx_ring_stats),
			GFP_KERNEL);
	if (!vsi_stat->tx_ring_stats)
		goto err_alloc_tx;

	vsi_stat->rx_ring_stats =
		kcalloc(vsi->alloc_rxq, sizeof(*vsi_stat->rx_ring_stats),
			GFP_KERNEL);
	if (!vsi_stat->rx_ring_stats)
		goto err_alloc_rx;

	pf->vsi_stats[vsi->idx] = vsi_stat;

	return 0;

err_alloc_rx:
	kfree(vsi_stat->rx_ring_stats);
err_alloc_tx:
	kfree(vsi_stat->tx_ring_stats);
	kfree(vsi_stat);
	pf->vsi_stats[vsi->idx] = NULL;
	return -ENOMEM;
}
```

vsi의 링의 상태를 나타내는 포인터의 실제 공간을 정의하는 함수임.