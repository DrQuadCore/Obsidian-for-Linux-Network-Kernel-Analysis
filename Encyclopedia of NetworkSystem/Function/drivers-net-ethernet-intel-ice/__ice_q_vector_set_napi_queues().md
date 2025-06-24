---
Parameter:
  - ice_q_vector
  - bool
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=__ice_q_vector_set_napi_queues()
/**
 * __ice_q_vector_set_napi_queues - Map queue[s] associated with the napi
 * @q_vector: q_vector pointer
 * @locked: is the rtnl_lock already held
 *
 * Associate the q_vector napi with all the queue[s] on the vector.
 * Caller indicates the lock status.
 */
void __ice_q_vector_set_napi_queues(struct ice_q_vector *q_vector, bool locked)
{
	struct ice_rx_ring *rx_ring;
	struct ice_tx_ring *tx_ring;

	ice_for_each_rx_ring(rx_ring, q_vector->rx)
		__ice_queue_set_napi(q_vector->vsi->netdev, rx_ring->q_index,
				     NETDEV_QUEUE_TYPE_RX, &q_vector->napi,
				     locked);

	ice_for_each_tx_ring(tx_ring, q_vector->tx)
		__ice_queue_set_napi(q_vector->vsi->netdev, tx_ring->q_index,
				     NETDEV_QUEUE_TYPE_TX, &q_vector->napi,
				     locked);
	/* Also set the interrupt number for the NAPI */
	netif_napi_set_irq(&q_vector->napi, q_vector->irq.virq);
}
```

> napi와 연관된 큐들을 매핑하는 함수. 여기서 net_device에 멤버로 있는 netdev_rx_queue와 netdev_queue에다가 해당 napi를 할당하게 된다. 그런데 이것은 기존의 ice_rx_ring과는 또 다른 Rx_queue이다.