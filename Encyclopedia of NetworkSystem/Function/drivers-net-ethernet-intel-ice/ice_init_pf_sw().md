---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_init_pf_sw()
static int ice_init_pf_sw(struct ice_pf *pf)
{
	bool dvm = ice_is_dvm_ena(&pf->hw);
	struct ice_vsi *vsi;
	int err;

	/* create switch struct for the switch element created by FW on boot */
	pf->first_sw = kzalloc(sizeof(*pf->first_sw), GFP_KERNEL);
	if (!pf->first_sw)
		return -ENOMEM;

	if (pf->hw.evb_veb)
		pf->first_sw->bridge_mode = BRIDGE_MODE_VEB;
	else
		pf->first_sw->bridge_mode = BRIDGE_MODE_VEPA;

	pf->first_sw->pf = pf;

	/* record the sw_id available for later use */
	pf->first_sw->sw_id = pf->hw.port_info->sw_id;

	err = ice_aq_set_port_params(pf->hw.port_info, dvm, NULL);
	if (err)
		goto err_aq_set_port_params;

	vsi = ice_pf_vsi_setup(pf, pf->hw.port_info); // [[ice_pf_vsi_setup()]]
	if (!vsi) {
		err = -ENOMEM;
		goto err_pf_vsi_setup;
	}

	return 0;

err_pf_vsi_setup:
err_aq_set_port_params:
	kfree(pf->first_sw);
	return err;
}
```

[[ice_pf_vsi_setup()]]
