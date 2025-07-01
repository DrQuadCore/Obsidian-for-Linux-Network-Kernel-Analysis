---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_send_vesion()
/**
 * ice_send_version - update firmware with driver version
 * @pf: PF struct
 *
 * Returns 0 on success, else error code
 */
static int ice_send_version(struct ice_pf *pf)
{
	struct ice_driver_ver dv;

	dv.major_ver = 0xff;
	dv.minor_ver = 0xff;
	dv.build_ver = 0xff;
	dv.subbuild_ver = 0;
	strscpy((char *)dv.driver_string, UTS_RELEASE,
		sizeof(dv.driver_string));
	return ice_aq_send_driver_ver(&pf->hw, &dv, NULL);
}
```

