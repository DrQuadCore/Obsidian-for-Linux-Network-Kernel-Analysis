---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_alloc_vsis()
static int ice_alloc_vsis(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	pf->num_alloc_vsi = pf->hw.func_caps.guar_num_vsi;
	if (!pf->num_alloc_vsi)
		return -EIO;

	if (pf->num_alloc_vsi > UDP_TUNNEL_NIC_MAX_SHARING_DEVICES) {
		dev_warn(dev,
			 "limiting the VSI count due to UDP tunnel limitation %d > %d\n",
			 pf->num_alloc_vsi, UDP_TUNNEL_NIC_MAX_SHARING_DEVICES);
		pf->num_alloc_vsi = UDP_TUNNEL_NIC_MAX_SHARING_DEVICES;
	}

	pf->vsi = devm_kcalloc(dev, pf->num_alloc_vsi, sizeof(*pf->vsi),
			       GFP_KERNEL);
	if (!pf->vsi)
		return -ENOMEM;

	pf->vsi_stats = devm_kcalloc(dev, pf->num_alloc_vsi,
				     sizeof(*pf->vsi_stats), GFP_KERNEL);
	if (!pf->vsi_stats) {
		devm_kfree(dev, pf->vsi);
		return -ENOMEM;
	}

	return 0;
}
```

> vsi들을 devm_kcalloc()으로 할당해주고 있음.