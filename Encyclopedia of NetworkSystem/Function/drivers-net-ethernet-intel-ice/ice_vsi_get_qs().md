---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_get_qs()
/**
 * ice_vsi_get_qs - Assign queues from PF to VSI
 * @vsi: the VSI to assign queues to
 *
 * Returns 0 on success and a negative value on error
 */
static int ice_vsi_get_qs(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	struct ice_qs_cfg tx_qs_cfg = {
		.qs_mutex = &pf->avail_q_mutex,
		.pf_map = pf->avail_txqs,
		.pf_map_size = pf->max_pf_txqs,
		.q_count = vsi->alloc_txq,
		.scatter_count = ICE_MAX_SCATTER_TXQS,
		.vsi_map = vsi->txq_map,
		.vsi_map_offset = 0,
		.mapping_mode = ICE_VSI_MAP_CONTIG
	};
	struct ice_qs_cfg rx_qs_cfg = {
		.qs_mutex = &pf->avail_q_mutex,
		.pf_map = pf->avail_rxqs,
		.pf_map_size = pf->max_pf_rxqs,
		.q_count = vsi->alloc_rxq,
		.scatter_count = ICE_MAX_SCATTER_RXQS,
		.vsi_map = vsi->rxq_map,
		.vsi_map_offset = 0,
		.mapping_mode = ICE_VSI_MAP_CONTIG
	};
	int ret;

	if (vsi->type == ICE_VSI_CHNL)
		return 0;

	ret = __ice_vsi_get_qs(&tx_qs_cfg);
	if (ret)
		return ret;
	vsi->tx_mapping_mode = tx_qs_cfg.mapping_mode;

	ret = __ice_vsi_get_qs(&rx_qs_cfg);
	if (ret)
		return ret;
	vsi->rx_mapping_mode = rx_qs_cfg.mapping_mode;

	return 0;
}
```

큐를 pf에서 vsi로 할당해주는 함수