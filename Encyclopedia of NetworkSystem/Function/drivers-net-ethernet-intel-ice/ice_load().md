---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_load()
/**
 * ice_load - load pf by init hw and starting VSI
 * @pf: pointer to the pf instance
 *
 * This function has to be called under devl_lock.
 */
int ice_load(struct ice_pf *pf)
{
	struct ice_vsi *vsi;
	int err;

	devl_assert_locked(priv_to_devlink(pf));

	vsi = ice_get_main_vsi(pf);

	/* init channel list */
	INIT_LIST_HEAD(&vsi->ch_list);

	err = ice_cfg_netdev(vsi);
	if (err)
		return err;

	/* Setup DCB netlink interface */
	ice_dcbnl_setup(vsi);

	err = ice_init_mac_fltr(pf);
	if (err)
		goto err_init_mac_fltr;

	err = ice_devlink_create_pf_port(pf);
	if (err)
		goto err_devlink_create_pf_port;

	SET_NETDEV_DEVLINK_PORT(vsi->netdev, &pf->devlink_port);

	err = ice_register_netdev(vsi);
	if (err)
		goto err_register_netdev;

	err = ice_tc_indir_block_register(vsi);
	if (err)
		goto err_tc_indir_block_register;

	ice_napi_add(vsi); // [[ice_napi_add()]]

	err = ice_init_rdma(pf);
	if (err)
		goto err_init_rdma;

	ice_init_features(pf);
	ice_service_task_restart(pf);

	clear_bit(ICE_DOWN, pf->state);

	return 0;

err_init_rdma:
	ice_tc_indir_block_unregister(vsi);
err_tc_indir_block_register:
	ice_unregister_netdev(vsi);
err_register_netdev:
	ice_devlink_destroy_pf_port(pf);
err_devlink_create_pf_port:
err_init_mac_fltr:
	ice_decfg_netdev(vsi);
	return err;
}
```

[[ice_napi_add()]]
