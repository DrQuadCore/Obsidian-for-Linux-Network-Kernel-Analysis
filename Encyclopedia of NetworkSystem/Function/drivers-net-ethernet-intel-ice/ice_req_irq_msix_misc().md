---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_main.c
---

```c title=ice_req_irq_msix_misc()
/**
 * ice_req_irq_msix_misc - Setup the misc vector to handle non queue events
 * @pf: board private structure
 *
 * This sets up the handler for MSIX 0, which is used to manage the
 * non-queue interrupts, e.g. AdminQ and errors. This is not used
 * when in MSI or Legacy interrupt mode.
 */
static int ice_req_irq_msix_misc(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u32 pf_intr_start_offset;
	struct msi_map irq;
	int err = 0;

	if (!pf->int_name[0])
		snprintf(pf->int_name, sizeof(pf->int_name) - 1, "%s-%s:misc",
			 dev_driver_string(dev), dev_name(dev));

	if (!pf->int_name_ll_ts[0])
		snprintf(pf->int_name_ll_ts, sizeof(pf->int_name_ll_ts) - 1,
			 "%s-%s:ll_ts", dev_driver_string(dev), dev_name(dev));
	/* Do not request IRQ but do enable OICR interrupt since settings are
	 * lost during reset. Note that this function is called only during
	 * rebuild path and not while reset is in progress.
	 */
	if (ice_is_reset_in_progress(pf->state))
		goto skip_req_irq;

	/* reserve one vector in irq_tracker for misc interrupts */
	irq = ice_alloc_irq(pf, false);
	if (irq.index < 0)
		return irq.index;

	pf->oicr_irq = irq;
	err = devm_request_threaded_irq(dev, pf->oicr_irq.virq, ice_misc_intr,
					ice_misc_intr_thread_fn, 0,
					pf->int_name, pf);
	if (err) {
		dev_err(dev, "devm_request_threaded_irq for %s failed: %d\n",
			pf->int_name, err);
		ice_free_irq(pf, pf->oicr_irq);
		return err;
	}

	/* reserve one vector in irq_tracker for ll_ts interrupt */
	if (!pf->hw.dev_caps.ts_dev_info.ts_ll_int_read)
		goto skip_req_irq;

	irq = ice_alloc_irq(pf, false);
	if (irq.index < 0)
		return irq.index;

	pf->ll_ts_irq = irq;
	err = devm_request_irq(dev, pf->ll_ts_irq.virq, ice_ll_ts_intr, 0,
			       pf->int_name_ll_ts, pf);
	if (err) {
		dev_err(dev, "devm_request_irq for %s failed: %d\n",
			pf->int_name_ll_ts, err);
		ice_free_irq(pf, pf->ll_ts_irq);
		return err;
	}

skip_req_irq:
	ice_ena_misc_vector(pf);

	ice_ena_ctrlq_interrupts(hw, pf->oicr_irq.index);
	/* This enables LL TS interrupt */
	pf_intr_start_offset = rd32(hw, PFINT_ALLOC) & PFINT_ALLOC_FIRST;
	if (pf->hw.dev_caps.ts_dev_info.ts_ll_int_read)
		wr32(hw, PFINT_SB_CTL,
		     ((pf->ll_ts_irq.index + pf_intr_start_offset) &
		      PFINT_SB_CTL_MSIX_INDX_M) | PFINT_SB_CTL_CAUSE_ENA_M);
	wr32(hw, GLINT_ITR(ICE_RX_ITR, pf->oicr_irq.index),
	     ITR_REG_ALIGN(ICE_ITR_8K) >> ICE_ITR_GRAN_S);

	ice_flush(hw);
	ice_irq_dynamic_ena(hw, NULL, NULL);

	return 0;
}
```
