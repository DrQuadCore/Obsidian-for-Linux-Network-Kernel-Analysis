---
Parameter:
  - ice_tx_ring
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_setup_tx_ring()
/**
 * ice_setup_tx_ring - Allocate the Tx descriptors
 * @tx_ring: the Tx ring to set up
 *
 * Return 0 on success, negative on error
 */
int ice_setup_tx_ring(struct ice_tx_ring *tx_ring) // [[ice_tx_ring]]
{
	struct device *dev = tx_ring->dev;
	u32 size;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(tx_ring->tx_buf);
	tx_ring->tx_buf =
		devm_kcalloc(dev, sizeof(*tx_ring->tx_buf), tx_ring->count,
			     GFP_KERNEL); // [[devm_kcalloc()]]
	if (!tx_ring->tx_buf)
		return -ENOMEM;

	/* round up to nearest page */
	size = ALIGN(tx_ring->count * sizeof(struct ice_tx_desc),
		     PAGE_SIZE);
	tx_ring->desc = dmam_alloc_coherent(dev, size, &tx_ring->dma,
					    GFP_KERNEL); // [[dmam_alloc_coherent()]]
	if (!tx_ring->desc) {
		dev_err(dev, "Unable to allocate memory for the Tx descriptor ring, size=%d\n",
			size);
		goto err;
	}

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->ring_stats->tx_stats.prev_pkt = -1;
	return 0;

err:
	devm_kfree(dev, tx_ring->tx_buf);
	tx_ring->tx_buf = NULL;
	return -ENOMEM;
}
```

[[ice_tx_ring]]
[[devm_kcalloc()]]
[[dmam_alloc_coherent()]]