---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_vsi_open()
/**
 * ice_vsi_open - Called when a network interface is made active
 * @vsi: the VSI to open
 *
 * Initialization of the VSI
 *
 * Returns 0 on success, negative value on error
 */
int ice_vsi_open(struct ice_vsi *vsi)
{
	char int_name[ICE_INT_NAME_STR_LEN];
	struct ice_pf *pf = vsi->back;
	int err;

	/* allocate descriptors */
	err = ice_vsi_setup_tx_rings(vsi); // [[ice_vsi_setup_tx_rings()]]
	if (err)
		goto err_setup_tx;

	err = ice_vsi_setup_rx_rings(vsi); // [[ice_vsi_setup_rx_rings()]]
	if (err)
		goto err_setup_rx;

	err = ice_vsi_cfg_lan(vsi); // [[ice_vsi_cfg_lan()]]
	if (err)
		goto err_setup_rx;

	snprintf(int_name, sizeof(int_name) - 1, "%s-%s",
		 dev_driver_string(ice_pf_to_dev(pf)), vsi->netdev->name);
	err = ice_vsi_req_irq_msix(vsi, int_name); // [[ice_vsi_req_irq_msix()]]
	if (err)
		goto err_setup_rx;

	ice_vsi_cfg_netdev_tc(vsi, vsi->tc_cfg.ena_tc);

	if (vsi->type == ICE_VSI_PF) {
		/* Notify the stack of the actual queue counts. */
		err = netif_set_real_num_tx_queues(vsi->netdev, vsi->num_txq);
		if (err)
			goto err_set_qs;

		err = netif_set_real_num_rx_queues(vsi->netdev, vsi->num_rxq);
		if (err)
			goto err_set_qs;
	}

	err = ice_up_complete(vsi); // [[ice_up_complete()]]
	if (err)
		goto err_up_complete;

	return 0;

err_up_complete:
	ice_down(vsi);
err_set_qs:
	ice_vsi_free_irq(vsi);
err_setup_rx:
	ice_vsi_free_rx_rings(vsi);
err_setup_tx:
	ice_vsi_free_tx_rings(vsi);

	return err;
}
```

[[ice_vsi_setup_tx_rings()]]
[[ice_vsi_setup_rx_rings()]]
[[ice_vsi_cfg_lan()]]
[[ice_vsi_req_irq_msix()]]
[[ice_up_complete()]]

vsi : virtual station interface, 가상화를 통해 여러 개의 논리 NIC로 사용할 수 있게 한다.

device라는 struct는 linux가 device를 관리하는데 사용함. “devm_” 은 device 메모리 관리 인터페이스를 통하므로, driver가 unload 되면 모든 자원을 해제하여 explicit하게 free를 할 필요가 없다는 장점이 있다.