---
Parameter:
  - ice_hw
  - ice_vsi
  - ice_q_vector
Return: void
Location: /drivers/net/ethernet/intel/ice/ice.h
---

```c title=ice_irq_dynamic_ena()
/**
 * ice_irq_dynamic_ena - Enable default interrupt generation settings
 * @hw: pointer to HW struct
 * @vsi: pointer to VSI struct, can be NULL
 * @q_vector: pointer to q_vector, can be NULL
 */
static inline void
ice_irq_dynamic_ena(struct ice_hw *hw, struct ice_vsi *vsi,
		    struct ice_q_vector *q_vector)
{
	u32 vector = (vsi && q_vector) ? q_vector->reg_idx :
				((struct ice_pf *)hw->back)->oicr_irq.index;
	int itr = ICE_ITR_NONE;
	u32 val;

	/* clear the PBA here, as this function is meant to clean out all
	 * previous interrupts and enable the interrupt
	 */
	val = GLINT_DYN_CTL_INTENA_M | GLINT_DYN_CTL_CLEARPBA_M |
	      (itr << GLINT_DYN_CTL_ITR_INDX_S);
	if (vsi)
		if (test_bit(ICE_VSI_DOWN, vsi->state))
			return;
	wr32(hw, GLINT_DYN_CTL(vector), val);
}
```

