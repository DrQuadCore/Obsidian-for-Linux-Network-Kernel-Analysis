---
Parameter:
  - net_device
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_open()
/**
 * ice_open - Called when a network interface becomes active
 * @netdev: network interface device structure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP). At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the netdev watchdog is enabled,
 * and the stack is notified that the interface is ready.
 *
 * Returns 0 on success, negative value on failure
 */
int ice_open(struct net_device *netdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_pf *pf = np->vsi->back;

	if (ice_is_reset_in_progress(pf->state)) {
		netdev_err(netdev, "can't open net device while reset is in progress");
		return -EBUSY;
	}

	return ice_open_internal(netdev); // [[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_open_internal()|ice_open_internal()]]
}
```

[[Encyclopedia of NetworkSystem/Function/drivers-net-ethernet-intel-ice/ice_open_internal()|ice_open_internal()]]

NIC가 활성화 되었을 때 네트워크 작동을 위해 초기화 하는 단계