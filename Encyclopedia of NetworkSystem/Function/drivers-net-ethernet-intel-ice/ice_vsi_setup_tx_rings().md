---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_vsi_setup_tx_rings()
/**
 * ice_vsi_setup_tx_rings - Allocate VSI Tx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int ice_vsi_setup_tx_rings(struct ice_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_txq) {
		dev_err(ice_pf_to_dev(vsi->back), "VSI %d has 0 Tx queues\n",
			vsi->vsi_num);
		return -EINVAL;
	}

	ice_for_each_txq(vsi, i) {
		struct ice_tx_ring *ring = vsi->tx_rings[i]; // [[ice_tx_ring]]

		if (!ring)
			return -EINVAL;

		if (vsi->netdev)
			ring->netdev = vsi->netdev;
		err = ice_setup_tx_ring(ring); // [[ice_setup_tx_ring()]]
 		if (err)
			break;
	}

	return err;
}
```

[[ice_tx_ring]]
[[ice_setup_tx_ring()]]

우선 num_txq를 통해 할당 된 tx queue의 갯수가 0이면 에러를 출력하고, 각각의 큐에 대하여, ice_tx_ring을 선언하여 ice_setup_tx_ring 함수를 호출하여 기본 설정을 시작한다.

struct ice_tx_ring ⇒ drivers/net/ethernet/intel/ice/ice_txrx.h 에서 볼 수 있음.

만들어진 모든 tx_ring은 ice_main.c의 ice_vsi_setup_tx_rings 에서 vsi→tx_rings[i]를 가르키는 포인터에서 수행하므로 결과적으로 vsi의 tx_rings 배열의 tx_ring들을 하나하나 설정하게 됨.