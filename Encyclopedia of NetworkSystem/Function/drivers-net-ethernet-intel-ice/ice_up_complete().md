---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_up_complete()
/**
 * ice_up_complete - Finish the last steps of bringing up a connection
 * @vsi: The VSI being configured
 *
 * Return 0 on success and negative value on error
 */
static int ice_up_complete(struct ice_vsi *vsi)
{
	struct ice_pf *pf = vsi->back;
	int err;

	ice_vsi_cfg_msix(vsi);

	/* Enable only Rx rings, Tx rings were enabled by the FW when the
	 * Tx queue group list was configured and the context bits were
	 * programmed using ice_vsi_cfg_txqs
	 */
	err = ice_vsi_start_all_rx_rings(vsi); // [[ice_vsi_start_all_rx_rings()]]
	if (err)
		return err;

	clear_bit(ICE_VSI_DOWN, vsi->state);
	ice_napi_enable_all(vsi); // [[ice_napi_enable_all()]]
	ice_vsi_ena_irq(vsi); // [[ice_vsi_ena_irq()]]

	if (vsi->port_info &&
	    (vsi->port_info->phy.link_info.link_info & ICE_AQ_LINK_UP) &&
	    vsi->netdev && vsi->type == ICE_VSI_PF) {
		ice_print_link_msg(vsi, true);
		netif_tx_start_all_queues(vsi->netdev); // [[netif_tx_start_all_queues()]]
		netif_carrier_on(vsi->netdev); // [[netif_carrier_on()]]
		ice_ptp_link_change(pf, pf->hw.pf_id, true);
	}

	/* Perform an initial read of the statistics registers now to
	 * set the baseline so counters are ready when interface is up
	 */
	ice_update_eth_stats(vsi);

	if (vsi->type == ICE_VSI_PF)
		ice_service_task_schedule(pf);

	return 0;
}
```

[[ice_vsi_start_all_rx_rings()]]
[[ice_napi_enable_all()]]
[[ice_vsi_ena_irq()]]
[[netif_tx_start_all_queues()]]
[[netif_carrier_on()]]

최종적으로 다 열렸는지 확인함.