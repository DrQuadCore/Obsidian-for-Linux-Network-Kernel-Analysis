---
Parameter:
  - ice_q_vector
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_enable_interrupt()
/**
 * ice_enable_interrupt - re-enable MSI-X interrupt
 * @q_vector: the vector associated with the interrupt to enable
 *
 * If the VSI is down, the interrupt will not be re-enabled. Also,
 * when enabling the interrupt always reset the wb_on_itr to false
 * and trigger a software interrupt to clean out internal state.
 */
static void ice_enable_interrupt(struct ice_q_vector *q_vector)
{
	struct ice_vsi *vsi = q_vector->vsi;
	bool wb_en = q_vector->wb_on_itr;
	u32 itr_val;

	if (test_bit(ICE_DOWN, vsi->state))
		return;

	/* trigger an ITR delayed software interrupt when exiting busy poll, to
	 * make sure to catch any pending cleanups that might have been missed
	 * due to interrupt state transition. If busy poll or poll isn't
	 * enabled, then don't update ITR, and just enable the interrupt.
	 */
	if (!wb_en) {
		itr_val = ice_buildreg_itr(ICE_ITR_NONE, 0);
	} else {
		q_vector->wb_on_itr = false;

		/* do two things here with a single write. Set up the third ITR
		 * index to be used for software interrupt moderation, and then
		 * trigger a software interrupt with a rate limit of 20K on
		 * software interrupts, this will help avoid high interrupt
		 * loads due to frequently polling and exiting polling.
		 */
		itr_val = ice_buildreg_itr(ICE_IDX_ITR2, ICE_ITR_20K);
		itr_val |= GLINT_DYN_CTL_SWINT_TRIG_M |
			   ICE_IDX_ITR2 << GLINT_DYN_CTL_SW_ITR_INDX_S |
			   GLINT_DYN_CTL_SW_ITR_INDX_ENA_M;
	}
	wr32(&vsi->back->hw, GLINT_DYN_CTL(q_vector->reg_idx), itr_val);
}

```
