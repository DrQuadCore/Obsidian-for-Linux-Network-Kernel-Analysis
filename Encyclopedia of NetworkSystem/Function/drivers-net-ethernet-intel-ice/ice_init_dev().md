---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_init_dev()
static int ice_init_dev(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int err;

	err = ice_init_hw(hw);
	if (err) {
		dev_err(dev, "ice_init_hw failed: %d\n", err);
		return err;
	}

	/* Some cards require longer initialization times
	 * due to necessity of loading FW from an external source.
	 * This can take even half a minute.
	 */
	if (ice_is_pf_c827(hw)) {
		err = ice_wait_for_fw(hw, 30000);
		if (err) {
			dev_err(dev, "ice_wait_for_fw timed out");
			return err;
		}
	}

	ice_init_feature_support(pf); // [[ice_init_feature_support()]]

	ice_request_fw(pf); // [[ice_request_fw()]]

	/* if ice_request_fw fails, ICE_FLAG_ADV_FEATURES bit won't be
	 * set in pf->state, which will cause ice_is_safe_mode to return
	 * true
	 */
	if (ice_is_safe_mode(pf)) {
		/* we already got function/device capabilities but these don't
		 * reflect what the driver needs to do in safe mode. Instead of
		 * adding conditional logic everywhere to ignore these
		 * device/function capabilities, override them.
		 */
		ice_set_safe_mode_caps(hw);
	}

	err = ice_init_pf(pf); // [[ice_init_pf()]]
	if (err) {
		dev_err(dev, "ice_init_pf failed: %d\n", err);
		goto err_init_pf;
	}

	pf->hw.udp_tunnel_nic.set_port = ice_udp_tunnel_set_port;
	pf->hw.udp_tunnel_nic.unset_port = ice_udp_tunnel_unset_port;
	pf->hw.udp_tunnel_nic.flags = UDP_TUNNEL_NIC_INFO_MAY_SLEEP;
	pf->hw.udp_tunnel_nic.shared = &pf->hw.udp_tunnel_shared;
	if (pf->hw.tnl.valid_count[TNL_VXLAN]) {
		pf->hw.udp_tunnel_nic.tables[0].n_entries =
			pf->hw.tnl.valid_count[TNL_VXLAN];
		pf->hw.udp_tunnel_nic.tables[0].tunnel_types =
			UDP_TUNNEL_TYPE_VXLAN;
	}
	if (pf->hw.tnl.valid_count[TNL_GENEVE]) {
		pf->hw.udp_tunnel_nic.tables[1].n_entries =
			pf->hw.tnl.valid_count[TNL_GENEVE];
		pf->hw.udp_tunnel_nic.tables[1].tunnel_types =
			UDP_TUNNEL_TYPE_GENEVE;
	}

	err = ice_init_interrupt_scheme(pf); // [[ice_init_interrupt_scheme()]]
	if (err) {
		dev_err(dev, "ice_init_interrupt_scheme failed: %d\n", err);
		err = -EIO;
		goto err_init_interrupt_scheme;
	}

	/* In case of MSIX we are going to setup the misc vector right here
	 * to handle admin queue events etc. In case of legacy and MSI
	 * the misc functionality and queue processing is combined in
	 * the same vector and that gets setup at open.
	 */
	err = ice_req_irq_msix_misc(pf); // [[ice_req_irq_msix_misc()]]
	if (err) {
		dev_err(dev, "setup of misc vector failed: %d\n", err);
		goto err_req_irq_msix_misc;
	}

	return 0;

err_req_irq_msix_misc:
	ice_clear_interrupt_scheme(pf);
err_init_interrupt_scheme:
	ice_deinit_pf(pf);
err_init_pf:
	ice_deinit_hw(hw);
	return err;
}
```

[[ice_init_feature_support()]]  
[[ice_request_fw()]]
[[ice_init_pf()]]
[[ice_init_interrupt_scheme()]]
[[ice_req_irq_msix_misc()]]

> pf로 dev를 가져옴