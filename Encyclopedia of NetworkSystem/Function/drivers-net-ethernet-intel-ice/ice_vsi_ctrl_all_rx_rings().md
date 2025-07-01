---
Parameter:
  - ice_vsi
  - bool
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_ctrl_all_rx_rings()
/**
 * ice_vsi_ctrl_all_rx_rings - Start or stop a VSI's Rx rings
 * @vsi: the VSI being configured
 * @ena: start or stop the Rx rings
 *
 * First enable/disable all of the Rx rings, flush any remaining writes, and
 * then verify that they have all been enabled/disabled successfully. This will
 * let all of the register writes complete when enabling/disabling the Rx rings
 * before waiting for the change in hardware to complete.
 */
static int ice_vsi_ctrl_all_rx_rings(struct ice_vsi *vsi, bool ena)
{
	int ret = 0;
	u16 i;

	ice_for_each_rxq(vsi, i)
		ice_vsi_ctrl_one_rx_ring(vsi, ena, i, false);

	ice_flush(&vsi->back->hw);

	ice_for_each_rxq(vsi, i) {
		ret = ice_vsi_wait_one_rx_ring(vsi, ena, i);
		if (ret)
			break;
	}

	return ret;
}
```
