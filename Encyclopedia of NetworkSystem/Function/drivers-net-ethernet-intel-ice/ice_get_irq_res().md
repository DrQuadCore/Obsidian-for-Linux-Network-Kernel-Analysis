---
Parameter:
  - ice_pf
  - bool
Return: ice_irq_entry
Location: /drivers/net/ethernet/intel/ice/ice_irq.c
---

```c title=ice_get_irq_res()
/**
 * ice_get_irq_res - get an interrupt resource
 * @pf: board private structure
 * @dyn_only: force entry to be dynamically allocated
 *
 * Allocate new irq entry in the free slot of the tracker. Since xarray
 * is used, always allocate new entry at the lowest possible index. Set
 * proper allocation limit for maximum tracker entries.
 *
 * Returns allocated irq entry or NULL on failure.
 */
static struct ice_irq_entry *ice_get_irq_res(struct ice_pf *pf, bool dyn_only)
{
	struct xa_limit limit = { .max = pf->irq_tracker.num_entries,
				  .min = 0 };
	unsigned int num_static = pf->irq_tracker.num_static;
	struct ice_irq_entry *entry;
	unsigned int index;
	int ret;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	/* skip preallocated entries if the caller says so */
	if (dyn_only)
		limit.min = num_static;

	ret = xa_alloc(&pf->irq_tracker.entries, &index, entry, limit,
		       GFP_KERNEL);

	if (ret) {
		kfree(entry);
		entry = NULL;
	} else {
		entry->index = index;
		entry->dynamic = index >= num_static;
	}

	return entry;
}
```

> irq_tracker에서 lowest possible index를 할당해줌. (msi-x에서 할당하는 Irq Resource)