---
Parameter:
  - device
Return: ice_pf
Location: /drivers/net/ethernet/intel/ice/ice_devlink..c
---

```c title=ice_allocate_pf()
struct ice_pf *ice_allocate_pf(struct device *dev)
{
	struct devlink *devlink;

	devlink = devlink_alloc(&ice_devlink_ops, sizeof(struct ice_pf), dev);
	if (!devlink)
		return NULL;

	/* Add an action to teardown the devlink when unwinding the driver */
	if (devm_add_action_or_reset(dev, ice_devlink_free, devlink))
		return NULL;

	return devlink_priv(devlink);
}
```

> pf를 할당함. 