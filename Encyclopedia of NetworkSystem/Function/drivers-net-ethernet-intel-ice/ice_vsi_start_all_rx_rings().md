---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_vsi_start_all_rx_rings()
/**
 * ice_vsi_start_all_rx_rings - start/enable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be enabled
 *
 * Returns 0 on success and a negative value on error
 */
int ice_vsi_start_all_rx_rings(struct ice_vsi *vsi)
{
	return ice_vsi_ctrl_all_rx_rings(vsi, true); // [[ice_vsi_ctrl_all_rx_rings()]]
}
```

[[ice_vsi_ctrl_all_rx_rings()]]

각각의 하나씩의 rx ring에 대하여 시작하고, 정상적으로 시작되는 것을 확인하고 함수 반환