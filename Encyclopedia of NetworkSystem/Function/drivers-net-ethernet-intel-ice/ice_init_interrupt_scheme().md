---
Parameter:
  - ice_pf
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_irq.c
---

```c title=ice_init_interrupt_scheme()
/**
 * ice_init_interrupt_scheme - Determine proper interrupt scheme
 * @pf: board private structure to initialize
 */
int ice_init_interrupt_scheme(struct ice_pf *pf)
{
	int total_vectors = pf->hw.func_caps.common_cap.num_msix_vectors;
	int vectors, max_vectors;

	vectors = ice_ena_msix_range(pf);

	if (vectors < 0)
		return -ENOMEM;

	if (pci_msix_can_alloc_dyn(pf->pdev))
		max_vectors = total_vectors;
	else
		max_vectors = vectors;

	ice_init_irq_tracker(pf, max_vectors, vectors);

	return 0;
}
```

