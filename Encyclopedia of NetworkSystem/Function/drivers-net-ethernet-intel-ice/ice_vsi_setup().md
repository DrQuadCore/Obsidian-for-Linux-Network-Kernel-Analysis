---
Parameter:
  - ice_pf
  - ice_vsi_cfg_params
Return: ice_vsi
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_setup()
/**
 * ice_vsi_setup - Set up a VSI by a given type
 * @pf: board private structure
 * @params: parameters to use when creating the VSI
 *
 * This allocates the sw VSI structure and its queue resources.
 *
 * Returns pointer to the successfully allocated and configured VSI sw struct on
 * success, NULL on failure.
 */
struct ice_vsi *
ice_vsi_setup(struct ice_pf *pf, struct ice_vsi_cfg_params *params)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_vsi *vsi;
	int ret;

	/* ice_vsi_setup can only initialize a new VSI, and we must have
	 * a port_info structure for it.
	 */
	if (WARN_ON(!(params->flags & ICE_VSI_FLAG_INIT)) ||
	    WARN_ON(!params->pi))
		return NULL;

	vsi = ice_vsi_alloc(pf);
	if (!vsi) {
		dev_err(dev, "could not allocate VSI\n");
		return NULL;
	}

	ret = ice_vsi_cfg(vsi, params); // [[ice_vsi_cfg()]]
	if (ret)
		goto err_vsi_cfg;

	/* Add switch rule to drop all Tx Flow Control Frames, of look up
	 * type ETHERTYPE from VSIs, and restrict malicious VF from sending
	 * out PAUSE or PFC frames. If enabled, FW can still send FC frames.
	 * The rule is added once for PF VSI in order to create appropriate
	 * recipe, since VSI/VSI list is ignored with drop action...
	 * Also add rules to handle LLDP Tx packets.  Tx LLDP packets need to
	 * be dropped so that VFs cannot send LLDP packets to reconfig DCB
	 * settings in the HW.
	 */
	if (!ice_is_safe_mode(pf) && vsi->type == ICE_VSI_PF) {
		ice_fltr_add_eth(vsi, ETH_P_PAUSE, ICE_FLTR_TX,
				 ICE_DROP_P ACKET);
		ice_cfg_sw_lldp(vsi, true, true);
	}

	if (!vsi->agg_node)
		ice_set_agg_vsi(vsi);

	return vsi;

err_vsi_cfg:
	ice_vsi_free(vsi);

	return NULL;
}
```

[[ice_vsi_cfg()]]