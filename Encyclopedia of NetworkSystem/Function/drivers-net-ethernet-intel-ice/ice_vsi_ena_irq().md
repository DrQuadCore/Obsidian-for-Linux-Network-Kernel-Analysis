---
Parameter:
  - ice_vsi
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_vsi_ena_irq()
/**
 * ice_vsi_ena_irq - Enable IRQ for the given VSI
 * @vsi: the VSI being configured
 */
static int ice_vsi_ena_irq(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->back->hw;
	int i;

	ice_for_each_q_vector(vsi, i)
		ice_irq_dynamic_ena(hw, vsi, vsi->q_vectors[i]); // [[ice_irq_dynamic_ena()]]
		//각각의 q_vector에 대하여 인터럽트를 활성화 함.

	ice_flush(hw);
	return 0;
}
```

[[ice_irq_dynamic_ena()]]