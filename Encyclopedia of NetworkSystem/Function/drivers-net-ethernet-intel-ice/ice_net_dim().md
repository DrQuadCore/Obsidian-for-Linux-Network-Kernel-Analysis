---
Parameter:
  - ice_q_vector
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_net_dim()
/**
 * ice_net_dim - Update net DIM algorithm
 * @q_vector: the vector associated with the interrupt
 *
 * Create a DIM sample and notify net_dim() so that it can possibly decide
 * a new ITR value based on incoming packets, bytes, and interrupts.
 *
 * This function is a no-op if the ring is not configured to dynamic ITR.
 */
static void ice_net_dim(struct ice_q_vector *q_vector)
{
	struct ice_ring_container *tx = &q_vector->tx;
	struct ice_ring_container *rx = &q_vector->rx;

	if (ITR_IS_DYNAMIC(tx)) {
		struct dim_sample dim_sample;

		__ice_update_sample(q_vector, tx, &dim_sample, true);
		net_dim(&tx->dim, dim_sample);
	}

	if (ITR_IS_DYNAMIC(rx)) {
		struct dim_sample dim_sample;

		__ice_update_sample(q_vector, rx, &dim_sample, false);
		net_dim(&rx->dim, dim_sample);
	}
}
```
