---
Parameter:
  - ice_vsi
  - ice_vsi_cfg_params
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_cfg()
/**
* ice_vsi_cfg - configure a previously allocated VSI
* @vsi: pointer to VSI
* @params: parameters used to configure this VSI
*/
int ice_vsi_cfg(struct ice_vsi *vsi, struct ice_vsi_cfg_params *params)
{
	struct ice_pf *pf = vsi->back;
	int ret;

	if (WARN_ON(params->type == ICE_VSI_VF && !params->vf))
		return -EINVAL;

	vsi->type = params->type;
	vsi->port_info = params->pi;

	/* For VSIs which don't have a connected VF, this will be NULL */
	vsi->vf = params->vf;

	ret = ice_vsi_cfg_def(vsi, params); // [[ice_vsi_cfg_def()]]
	if (ret)
		return ret;

	ret = ice_vsi_cfg_tc_lan(vsi->back, vsi);
	if (ret)
		ice_vsi_decfg(vsi);

	if (vsi->type == ICE_VSI_CTRL) {
		if (vsi->vf) {
			WARN_ON(vsi->vf->ctrl_vsi_idx != ICE_NO_VSI);
			vsi->vf->ctrl_vsi_idx = vsi->idx;
		} else {
			WARN_ON(pf->ctrl_vsi_idx != ICE_NO_VSI);
			pf->ctrl_vsi_idx = vsi->idx;
		}
	}

	return ret;
}

```

[[ice_vsi_cfg_def()]]