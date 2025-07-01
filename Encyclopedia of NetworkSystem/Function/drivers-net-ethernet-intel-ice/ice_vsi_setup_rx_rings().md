---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_vsi_setup_rx_rings()
/**
 * ice_vsi_setup_rx_rings - Allocate VSI Rx queue resources
 * @vsi: VSI having resources allocated
 *
 * Return 0 on success, negative on failure
 */
int ice_vsi_setup_rx_rings(struct ice_vsi *vsi)
{
	int i, err = 0;

	if (!vsi->num_rxq) {
		dev_err(ice_pf_to_dev(vsi->back), "VSI %d has 0 Rx queues\n",
			vsi->vsi_num);
		return -EINVAL;
	}

	ice_for_each_rxq(vsi, i) {
		struct ice_rx_ring *ring = vsi->rx_rings[i]; // [[ice_rx_ring]]

		if (!ring)
			return -EINVAL;

		if (vsi->netdev)
			ring->netdev = vsi->netdev;
		err = ice_setup_rx_ring(ring); // [[ice_setup_rx_ring()]]
		if (err)
			break;
	}

	return err;
}
```

[[ice_rx_ring]]
[[ice_setup_rx_ring()]]

우선 vsi의 num_rxq를 통해 할당 된 rx queue의 갯수가 0이면 에러를 출력하고, 각각의 큐에 대하여, ice_rx_ring을 선언하여 ice_setup_rx_ring 함수를 호출하여 기본 설정을 시작한다.

ice_rx_ring struct에서 u16 q_index는 해당 링의 Queue number로, CPU가 수신 링들을 구분할 때 사용하는 번호이다. napi에서 skb를 만들 때 해당 번호 + 1 을 skb→queue_mapping에다가 넣어준다. 다음으로 next_to_use와 next_to_clean이 있는데, 이는 일반적인 큐와 비슷하다. push를 하면 next_to_use를 사용하게 되고, napi로 인해 skb로 만들어져 네트워크 스택으로 전달 될 경우 next_to_clean을 사용하여 인덱스에 접근하게 된다. 마찬가지로 index가 overflow라면 0으로 돌아가게 된다.