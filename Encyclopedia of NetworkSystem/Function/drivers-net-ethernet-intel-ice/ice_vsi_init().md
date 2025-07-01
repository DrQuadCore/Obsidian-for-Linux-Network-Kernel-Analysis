---
Parameter:
  - ice_vsi
  - u32
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_init()
/**
 * ice_vsi_init - Create and initialize a VSI
 * @vsi: the VSI being configured
 * @vsi_flags: VSI configuration flags
 *
 * Set ICE_FLAG_VSI_INIT to initialize a new VSI context, clear it to
 * reconfigure an existing context.
 *
 * This initializes a VSI context depending on the VSI type to be added and
 * passes it down to the add_vsi aq command to create a new VSI.
 */
static int ice_vsi_init(struct ice_vsi *vsi, u32 vsi_flags)
{
	struct ice_pf *pf = vsi->back;
	struct ice_hw *hw = &pf->hw;
	struct ice_vsi_ctx *ctxt;
	struct device *dev;
	int ret = 0;

	dev = ice_pf_to_dev(pf);
	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_LB:
	case ICE_VSI_PF:
		ctxt->flags = ICE_AQ_VSI_TYPE_PF;
		break;
	case ICE_VSI_SWITCHDEV_CTRL:
	case ICE_VSI_CHNL:
		ctxt->flags = ICE_AQ_VSI_TYPE_VMDQ2;
		break;
	case ICE_VSI_VF:
		ctxt->flags = ICE_AQ_VSI_TYPE_VF;
		/* VF number here is the absolute VF number (0-255) */
		ctxt->vf_num = vsi->vf->vf_id + hw->func_caps.vf_base_id;
		break;
	default:
		ret = -ENODEV;
		goto out;
	}

	/* Handle VLAN pruning for channel VSI if main VSI has VLAN
	 * prune enabled
	 */
	if (vsi->type == ICE_VSI_CHNL) {
		struct ice_vsi *main_vsi;

		main_vsi = ice_get_main_vsi(pf);
		if (main_vsi && ice_vsi_is_vlan_pruning_ena(main_vsi))
			ctxt->info.sw_flags2 |=
				ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;
		else
			ctxt->info.sw_flags2 &=
				~ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;
	}

	ice_set_dflt_vsi_ctx(hw, ctxt);
	if (test_bit(ICE_FLAG_FD_ENA, pf->flags))
		ice_set_fd_vsi_ctx(ctxt, vsi);
	/* if the switch is in VEB mode, allow VSI loopback */
	if (vsi->vsw->bridge_mode == BRIDGE_MODE_VEB)
		ctxt->info.sw_flags |= ICE_AQ_VSI_SW_FLAG_ALLOW_LB;

	/* Set LUT type and HASH type if RSS is enabled */
	if (test_bit(ICE_FLAG_RSS_ENA, pf->flags) &&
	    vsi->type != ICE_VSI_CTRL) {
		ice_set_rss_vsi_ctx(ctxt, vsi);
		/* if updating VSI context, make sure to set valid_section:
		 * to indicate which section of VSI context being updated
		 */
		if (!(vsi_flags & ICE_VSI_FLAG_INIT))
			ctxt->info.valid_sections |=
				cpu_to_le16(ICE_AQ_VSI_PROP_Q_OPT_VALID);
	}

	ctxt->info.sw_id = vsi->port_info->sw_id;
	if (vsi->type == ICE_VSI_CHNL) {
		ice_chnl_vsi_setup_q_map(vsi, ctxt);
	} else {
		ret = ice_vsi_setup_q_map(vsi, ctxt);
		if (ret)
			goto out;

		if (!(vsi_flags & ICE_VSI_FLAG_INIT))
			/* means VSI being updated */
			/* must to indicate which section of VSI context are
			 * being modified
			 */
			ctxt->info.valid_sections |=
				cpu_to_le16(ICE_AQ_VSI_PROP_RXQ_MAP_VALID);
	}

	/* Allow control frames out of main VSI */
	if (vsi->type == ICE_VSI_PF) {
		ctxt->info.sec_flags |= ICE_AQ_VSI_SEC_FLAG_ALLOW_DEST_OVRD;
		ctxt->info.valid_sections |=
			cpu_to_le16(ICE_AQ_VSI_PROP_SECURITY_VALID);
	}

	if (vsi_flags & ICE_VSI_FLAG_INIT) {
		ret = ice_add_vsi(hw, vsi->idx, ctxt, NULL);
		if (ret) {
			dev_err(dev, "Add VSI failed, err %d\n", ret);
			ret = -EIO;
			goto out;
		}
	} else {
		ret = ice_update_vsi(hw, vsi->idx, ctxt, NULL);
		if (ret) {
			dev_err(dev, "Update VSI failed, err %d\n", ret);
			ret = -EIO;
			goto out;
		}
	}

	/* keep context for update VSI operations */
	vsi->info = ctxt->info;

	/* record VSI number returned */
	vsi->vsi_num = ctxt->vsi_num;

out:
	kfree(ctxt);
	return ret;
}
```

vsi→type에 따라 달라짐.