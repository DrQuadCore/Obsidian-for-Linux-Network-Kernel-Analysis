---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_base.c
---

```c title=ice_vsi_cfg_rxqs()
/**
 * ice_vsi_cfg_rxqs - Configure the VSI for Rx
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Rx VSI for operation.
 */
int ice_vsi_cfg_rxqs(struct ice_vsi *vsi)
{
	u16 i;

	if (vsi->type == ICE_VSI_VF)
		goto setup_rings;

	ice_vsi_cfg_frame_size(vsi);
setup_rings:
	/* set up individual rings */
	ice_for_each_rxq(vsi, i) {
		int err = ice_vsi_cfg_rxq(vsi->rx_rings[i]); // [[ice_vsi_cfg_rxq()]]

		if (err)
			return err;
	}

	return 0;
}
```

[[ice_vsi_cfg_rxq()]]