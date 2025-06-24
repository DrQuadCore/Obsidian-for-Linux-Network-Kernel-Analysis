---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_init_devlink()
static int ice_init_devlink(struct ice_pf *pf)
{
	int err;

	err = ice_devlink_register_params(pf);
	if (err)
		return err;

	ice_devlink_init_regions(pf);
	ice_devlink_register(pf);

	return 0;
}
```

