---
Parameter:
  - ice_pf
  - bool
Return: msi_map
Location: /drivers/net/ethernet/intel/ice/ice_irq.c
---

```c title=ice_alloc_irq()
/**
 * ice_alloc_irq - Allocate new interrupt vector
 * @pf: board private structure
 * @dyn_only: force dynamic allocation of the interrupt
 *
 * Allocate new interrupt vector for a given owner id.
 * return struct msi_map with interrupt details and track
 * allocated interrupt appropriately.
 *
 * This function reserves new irq entry from the irq_tracker.
 * if according to the tracker information all interrupts that
 * were allocated with ice_pci_alloc_irq_vectors are already used
 * and dynamically allocated interrupts are supported then new
 * interrupt will be allocated with pci_msix_alloc_irq_at.
 *
 * Some callers may only support dynamically allocated interrupts.
 * This is indicated with dyn_only flag.
 *
 * On failure, return map with negative .index. The caller
 * is expected to check returned map index.
 *
 */
struct msi_map ice_alloc_irq(struct ice_pf *pf, bool dyn_only)
{
	int sriov_base_vector = pf->sriov_base_vector;
	struct msi_map map = { .index = -ENOENT };
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_irq_entry *entry;

	entry = ice_get_irq_res(pf, dyn_only); // [[ice_get_irq_res()]]
	if (!entry)
		return map;

	/* fail if we're about to violate SRIOV vectors space */
	if (sriov_base_vector && entry->index >= sriov_base_vector)
		goto exit_free_res;

	if (pci_msix_can_alloc_dyn(pf->pdev) && entry->dynamic) {
		map = pci_msix_alloc_irq_at(pf->pdev, entry->index, NULL);
		if (map.index < 0)
			goto exit_free_res;
		dev_dbg(dev, "allocated new irq at index %d\n", map.index);
	} else {
		map.index = entry->index;
		map.virq = pci_irq_vector(pf->pdev, map.index);
	}

	return map;

exit_free_res:
	dev_err(dev, "Could not allocate irq at idx %d\n", entry->index);
	ice_free_irq_res(pf, entry->index);
	return map;
}
```

[[ice_get_irq_res()]]

return이 msi_map임.

dyn_alloc에 따라 pci_msix_alloc_irq_at() 혹은 pci_irq_vector() 등으로 msi_map을 구성함.

⇒ index는 msi 인덱스이고, virq는 연관된 리눅스 인터럽트 번호임. virq 번호는 vsi의 base address에 저장된 irq로부터 index만큼 떨어져 있다고 보면 됨. 연속적인 인터럽트 번호를 가지는 것임.