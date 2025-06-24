---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_vsi_cfg_lan()
/**
 * ice_vsi_cfg_lan - Setup the VSI lan related config
 * @vsi: the VSI being configured
 *
 * Return 0 on success and negative value on error
 */
int ice_vsi_cfg_lan(struct ice_vsi *vsi)
{
	int err;

	if (vsi->netdev && vsi->type == ICE_VSI_PF) {
		ice_set_rx_mode(vsi->netdev);

		err = ice_vsi_vlan_setup(vsi);
		if (err)
			return err;
	}
	ice_vsi_cfg_dcb_rings(vsi);

	err = ice_vsi_cfg_lan_txqs(vsi);
	if (!err && ice_is_xdp_ena_vsi(vsi))
		err = ice_vsi_cfg_xdp_txqs(vsi);
	if (!err)
		err = ice_vsi_cfg_rxqs(vsi); // [[ice_vsi_cfg_rxqs()]]

	return err;
}
```

[[ice_vsi_cfg_rxqs()]]