---
Parameter:
  - ice_pf
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_init_wakeup()
static void ice_init_wakeup(struct ice_pf *pf)
{
	/* Save wakeup reason register for later use */
	pf->wakeup_reason = rd32(&pf->hw, PFPM_WUS);

	/* check for a power management event */
	ice_print_wake_reason(pf);

	/* clear wake status, all bits */
	wr32(&pf->hw, PFPM_WUS, U32_MAX);

	/* Disable WoL at init, wait for user to enable */
	device_set_wakeup_enable(ice_pf_to_dev(pf), false);
}
```

