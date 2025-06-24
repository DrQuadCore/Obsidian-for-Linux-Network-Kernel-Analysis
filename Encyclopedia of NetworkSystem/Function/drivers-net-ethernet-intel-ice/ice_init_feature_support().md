---
Parameter:
  - ice_pf
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_init_feature_support()
/**
 * ice_init_feature_support
 * @pf: pointer to the struct ice_pf instance
 *
 * called during init to setup supported feature
 */
void ice_init_feature_support(struct ice_pf *pf)
{
	switch (pf->hw.device_id) {
	case ICE_DEV_ID_E810C_BACKPLANE:
	case ICE_DEV_ID_E810C_QSFP:
	case ICE_DEV_ID_E810C_SFP:
	case ICE_DEV_ID_E810_XXV_BACKPLANE:
	case ICE_DEV_ID_E810_XXV_QSFP:
	case ICE_DEV_ID_E810_XXV_SFP:
		ice_set_feature_support(pf, ICE_F_DSCP);
		if (ice_is_phy_rclk_in_netlist(&pf->hw))
			ice_set_feature_support(pf, ICE_F_PHY_RCLK);
		/* If we don't own the timer - don't enable other caps */
		if (!ice_pf_src_tmr_owned(pf))
			break;
		if (ice_is_cgu_in_netlist(&pf->hw))
			ice_set_feature_support(pf, ICE_F_CGU);
		if (ice_is_clock_mux_in_netlist(&pf->hw))
			ice_set_feature_support(pf, ICE_F_SMA_CTRL);
		if (ice_gnss_is_gps_present(&pf->hw))
			ice_set_feature_support(pf, ICE_F_GNSS);
		break;
	default:
		break;
	}
}
```

