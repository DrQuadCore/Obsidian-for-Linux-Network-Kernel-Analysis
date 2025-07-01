---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_init()
static int ice_init(struct ice_pf *pf)
{
	int err;

	err = ice_init_dev(pf); // [[ice_init_dev()]]
	if (err)
		return err;

	err = ice_alloc_vsis(pf); // [[ice_alloc_vsis()]]
	if (err)
		goto err_alloc_vsis;

	err = ice_init_pf_sw(pf); // [[ice_init_pf_sw()]]
	if (err)
		goto err_init_pf_sw;

	ice_init_wakeup(pf); // [[ice_init_wakeup()]]

	err = ice_init_link(pf); // [[ice_init_link()]]
	if (err)
		goto err_init_link;

	err = ice_send_version(pf); // [[ice_send_version()]]
	if (err)
		goto err_init_link;

	ice_verify_cacheline_size(pf); // [[ice_verify_cacheline_size()]]

	if (ice_is_safe_mode(pf))
		ice_set_safe_mode_vlan_cfg(pf);
	else
		/* print PCI link speed and width */
		pcie_print_link_status(pf->pdev);

	/* ready to go, so clear down state bit */
	clear_bit(ICE_DOWN, pf->state);
	clear_bit(ICE_SERVICE_DIS, pf->state);

	/* since everything is good, start the service timer */
	mod_timer(&pf->serv_tmr, round_jiffies(jiffies + pf->serv_tmr_period));

	return 0;

err_init_link:
	ice_deinit_pf_sw(pf);
err_init_pf_sw:
	ice_dealloc_vsis(pf);
err_alloc_vsis:
	ice_deinit_dev(pf);
	return err;
}
```

[[ice_init_dev()]]  
[[ice_alloc_vsis()]]  
[[ice_init_pf_sw()]]  
[[ice_init_wakeup()]]  
[[ice_init_link()]]  
[[ice_send_version()]]  
[[ice_verify_cacheline_size()]]
