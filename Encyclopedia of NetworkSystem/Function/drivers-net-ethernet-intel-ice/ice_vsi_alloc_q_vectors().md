---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_base.c
---

```c title=ice_vsi_alloc_q_vectors()
/**
 * ice_vsi_alloc_q_vectors - Allocate memory for interrupt vectors
 * @vsi: the VSI being configured
 *
 * We allocate one q_vector per queue interrupt. If allocation fails we
 * return -ENOMEM.
 */
int ice_vsi_alloc_q_vectors(struct ice_vsi *vsi)
{
	struct device *dev = ice_pf_to_dev(vsi->back);
	u16 v_idx;
	int err;

	if (vsi->q_vectors[0]) {
		dev_dbg(dev, "VSI %d has existing q_vectors\n", vsi->vsi_num);
		return -EEXIST;
	}

	for (v_idx = 0; v_idx < vsi->num_q_vectors; v_idx++) {
		err = ice_vsi_alloc_q_vector(vsi, v_idx); // [[ice_vsi_alloc_q_vector()]]
		if (err)
			goto err_out;
	}

	return 0;

err_out:
	while (v_idx--)
		ice_free_q_vector(vsi, v_idx);

	dev_err(dev, "Failed to allocate %d q_vector for VSI %d, ret=%d\n",
		vsi->num_q_vectors, vsi->vsi_num, err);
	vsi->num_q_vectors = 0;
	return err;
}
```

[[ice_vsi_alloc_q_vector()]]
