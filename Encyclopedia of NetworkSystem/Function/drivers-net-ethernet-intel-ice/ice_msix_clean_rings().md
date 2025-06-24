---
Parameter:
  - int
  - void
Return: irqreturn_t
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_msix_clean_rings()
/**
 * ice_msix_clean_rings - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
static irqreturn_t ice_msix_clean_rings(int __always_unused irq, void *data)
{
	struct ice_q_vector *q_vector = (struct ice_q_vector *)data;

	if (!q_vector->tx.tx_ring && !q_vector->rx.rx_ring)
		return IRQ_HANDLED;

	q_vector->total_events++;

	napi_schedule(&q_vector->napi); // [[napi_schedule()]]

	return IRQ_HANDLED;
}
```

[[napi_schedule()]]

void `*data`를 통해 ice_q_vector가 들어오고 여기서 napi struct를 볼 수 있다. —> hardware interrupt임. napi 스케쥴링 이후 종료.