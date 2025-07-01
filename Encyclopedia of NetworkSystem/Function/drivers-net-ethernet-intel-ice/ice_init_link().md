---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_init_link()
static int ice_init_link(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	err = ice_init_link_events(pf->hw.port_info);
	if (err) {
		dev_err(dev, "ice_init_link_events failed: %d\n", err);
		return err;
	}

	/* not a fatal error if this fails */
	err = ice_init_nvm_phy_type(pf->hw.port_info);
	if (err)
		dev_err(dev, "ice_init_nvm_phy_type failed: %d\n", err);

	/* not a fatal error if this fails */
	err = ice_update_link_info(pf->hw.port_info);
	if (err)
		dev_err(dev, "ice_update_link_info failed: %d\n", err);

	ice_init_link_dflt_override(pf->hw.port_info);

	ice_check_link_cfg_err(pf,
			       pf->hw.port_info->phy.link_info.link_cfg_err);

	/* if media available, initialize PHY settings */
	if (pf->hw.port_info->phy.link_info.link_info &
	    ICE_AQ_MEDIA_AVAILABLE) {
		/* not a fatal error if this fails */
		err = ice_init_phy_user_cfg(pf->hw.port_info);
		if (err)
			dev_err(dev, "ice_init_phy_user_cfg failed: %d\n", err);

		if (!test_bit(ICE_FLAG_LINK_DOWN_ON_CLOSE_ENA, pf->flags)) {
			struct ice_vsi *vsi = ice_get_main_vsi(pf);

			if (vsi)
				ice_configure_phy(vsi);
		}
	} else {
		set_bit(ICE_FLAG_NO_MEDIA, pf->flags);
	}

	return err;
}
```

