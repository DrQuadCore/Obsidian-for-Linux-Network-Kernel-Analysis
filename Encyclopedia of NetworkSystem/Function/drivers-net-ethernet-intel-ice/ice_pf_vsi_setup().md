---
Parameter:
  - ice_pf
  - ice_port_info
Return: ice_vsi
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_pf_vsi_setup()
/**
 * ice_pf_vsi_setup - Set up a PF VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 *
 * Returns pointer to the successfully allocated VSI software struct
 * on success, otherwise returns NULL on failure.
 */
static struct ice_vsi *
ice_pf_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi)
{
	struct ice_vsi_cfg_params params = {};

	params.type = ICE_VSI_PF;
	params.pi = pi;
	params.flags = ICE_VSI_FLAG_INIT;

	return ice_vsi_setup(pf, &params); // [[ice_vsi_setup()]]
}
```

[[ice_vsi_setup()]]