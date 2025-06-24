---
Parameter:
  - ice_vsi
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_napi_enable_all()
/**
 * ice_napi_enable_all - Enable NAPI for all q_vectors in the VSI
 * @vsi: the VSI being configured
 */
static void ice_napi_enable_all(struct ice_vsi *vsi)
{
	int q_idx;

	if (!vsi->netdev)
		return;

	ice_for_each_q_vector(vsi, q_idx) {
		struct ice_q_vector *q_vector = vsi->q_vectors[q_idx];

		ice_init_moderation(q_vector);

		if (q_vector->rx.rx_ring || q_vector->tx.tx_ring)
			napi_enable(&q_vector->napi);
	}
}
```
