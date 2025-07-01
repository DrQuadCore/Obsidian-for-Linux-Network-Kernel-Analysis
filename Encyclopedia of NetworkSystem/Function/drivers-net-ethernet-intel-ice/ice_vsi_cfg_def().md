---
Parameter:
  - ice_vsi
  - ice_vsi_cfg_params
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_cfg_def()
/**
 * ice_vsi_cfg_def - configure default VSI based on the type
 * @vsi: pointer to VSI
 * @params: the parameters to configure this VSI with
 */
static int
ice_vsi_cfg_def(struct ice_vsi *vsi, struct ice_vsi_cfg_params *params)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	struct ice_pf *pf = vsi->back;
	int ret;

	vsi->vsw = pf->first_sw;

	ret = ice_vsi_alloc_def(vsi, params->ch); // [[ice_vsi_alloc_def()]]
	if (ret)
		return ret;

	/* allocate memory for Tx/Rx ring stat pointers */
	ret = ice_vsi_alloc_stat_arrays(vsi); // [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_vsi_alloc_stat_arrays().md|ice_vsi_alloc_stat_arrays()]]
	if (ret)
		goto unroll_vsi_alloc;

	ice_alloc_fd_res(vsi);

	ret = ice_vsi_get_qs(vsi); // [[ice_vsi_get_qs()]]
	if (ret) {
		dev_err(dev, "Failed to allocate queues. vsi->idx = %d\n",
			vsi->idx);
		goto unroll_vsi_alloc_stat;
	}

	/* set RSS capabilities */
	ice_vsi_set_rss_params(vsi);

	/* set TC configuration */
	ice_vsi_set_tc_cfg(vsi);

	/* create the VSI */
	ret = ice_vsi_init(vsi, params->flags); // [[ice_vsi_init()]]
	if (ret)
		goto unroll_get_qs;

	ice_vsi_init_vlan_ops(vsi);

	switch (vsi->type) {
	case ICE_VSI_CTRL:
	case ICE_VSI_SWITCHDEV_CTRL:
	case ICE_VSI_PF:
		ret = ice_vsi_alloc_q_vectors(vsi); // [[ice_vsi_alloc_q_vectors()]]
		if (ret)
			goto unroll_vsi_init;

		ret = ice_vsi_alloc_rings(vsi); // [[ice_vsi_alloc_rings()]]
		if (ret)
			goto unroll_vector_base;

		ret = ice_vsi_alloc_ring_stats(vsi); // [[ice_vsi_alloc_ring_stats()]]
		if (ret)
			goto unroll_vector_base;

		ice_vsi_map_rings_to_vectors(vsi); //PF일때만 해당, [[ice_vsi_map_rings_to_vectors()]]

		/* Associate q_vector rings to napi */
		ice_vsi_set_napi_queues(vsi);

		vsi->stat_offsets_loaded = false;

		if (ice_is_xdp_ena_vsi(vsi)) {
			ret = ice_vsi_determine_xdp_res(vsi);
			if (ret)
				goto unroll_vector_base;
			ret = ice_prepare_xdp_rings(vsi, vsi->xdp_prog);
			if (ret)
				goto unroll_vector_base;
		}

		/* ICE_VSI_CTRL does not need RSS so skip RSS processing */
		if (vsi->type != ICE_VSI_CTRL)
			/* Do not exit if configuring RSS had an issue, at
			 * least receive traffic on first queue. Hence no
			 * need to capture return value
			 */
			if (test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
				ice_vsi_cfg_rss_lut_key(vsi);
				ice_vsi_set_rss_flow_fld(vsi);
			}
		ice_init_arfs(vsi);
		break;
	case ICE_VSI_CHNL:
		if (test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
			ice_vsi_cfg_rss_lut_key(vsi);
			ice_vsi_set_rss_flow_fld(vsi);
		}
		break;
	case ICE_VSI_VF:
		/* VF driver will take care of creating netdev for this type and
		 * map queues to vectors through Virtchnl, PF driver only
		 * creates a VSI and corresponding structures for bookkeeping
		 * purpose
		 */
		ret = ice_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto unroll_vsi_init;

		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = ice_vsi_alloc_ring_stats(vsi);
		if (ret)
			goto unroll_vector_base;

		vsi->stat_offsets_loaded = false;

		/* Do not exit if configuring RSS had an issue, at least
		 * receive traffic on first queue. Hence no need to capture
		 * return value
		 */
		if (test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
			ice_vsi_cfg_rss_lut_key(vsi);
			ice_vsi_set_vf_rss_flow_fld(vsi);
		}
		break;
	case ICE_VSI_LB:
		ret = ice_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_vsi_init;

		ret = ice_vsi_alloc_ring_stats(vsi);
		if (ret)
			goto unroll_vector_base;

		break;
	default:
		/* clean up the resources and exit */
		ret = -EINVAL;
		goto unroll_vsi_init;
	}

	return 0;

unroll_vector_base:
	/* reclaim SW interrupts back to the common pool */
unroll_alloc_q_vector:
	ice_vsi_free_q_vectors(vsi);
unroll_vsi_init:
	ice_vsi_delete_from_hw(vsi);
unroll_get_qs:
	ice_vsi_put_qs(vsi);
unroll_vsi_alloc_stat:
	ice_vsi_free_stats(vsi);
unroll_vsi_alloc:
	ice_vsi_free_arrays(vsi);
	return ret;
}
```

[[ice_vsi_alloc_def()]]
[[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_vsi_alloc_stat_arrays().md|ice_vsi_alloc_stat_arrays()]]
[[ice_vsi_get_qs()]]
[[ice_vsi_init()]]
[[ice_vsi_alloc_q_vectors()]]
[[ice_vsi_alloc_rings()]]
[[ice_vsi_alloc_ring_stats()]]
[[ice_vsi_map_rings_to_vectors()]]