---
Parameter:
  - ice_rx_ring
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
sticker: ""
---

```c title=ice_setup_rx_ring()
/**
 * ice_setup_rx_ring - Allocate the Rx descriptors
 * @rx_ring: the Rx ring to set up
 *
 * Return 0 on success, negative on error
 */
int ice_setup_rx_ring(struct ice_rx_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	u32 size;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(rx_ring->rx_buf);
	rx_ring->rx_buf =
		kcalloc(rx_ring->count, sizeof(*rx_ring->rx_buf), GFP_KERNEL);
	if (!rx_ring->rx_buf)
		return -ENOMEM;

	/* round up to nearest page */
	size = ALIGN(rx_ring->count * sizeof(union ice_32byte_rx_desc),
		     PAGE_SIZE);
	rx_ring->desc = dmam_alloc_coherent(dev, size, &rx_ring->dma,
					    GFP_KERNEL); // [[dmam_alloc_coherent()]]
	if (!rx_ring->desc) {
		dev_err(dev, "Unable to allocate memory for the Rx descriptor ring, size=%d\n",
			size);
		goto err;
	}

	rx_ring->next_to_use = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->first_desc = 0;

	if (ice_is_xdp_ena_vsi(rx_ring->vsi))
		WRITE_ONCE(rx_ring->xdp_prog, rx_ring->vsi->xdp_prog);

	return 0;

err:
	kfree(rx_ring->rx_buf);
	rx_ring->rx_buf = NULL;
	return -ENOMEM;
}
```

[[dmam_alloc_coherent()]]

rx_ring→rx_buf를 kcalloc을 통해 새로 선언하게 됨. 이때, rx_ring→count만큼의 배열로 선언되게 됨.

이후 ALIGN을 통해 PAGE_SIZE 크기의 단위로 몇 바이트가 필요한지 계산하여 size에 저장하게 됨. 이때, 만약 4500바이트의 rx_buf array이고, PAGE_SIZE가 4096이라면, size는 8182가 됨. 이는 ice_32byte_rx_desc라는 구조체를 할당하기 위함임. rx_ring→dma에 해당 주소를 할당하며, 이 때 담고자 하는 정보는 각각의 버퍼에 대한 디스크립터임.

만들어진 모든 rx_ring은 ice_main.c의 ice_vsi_setup_rx_rings 에서 vsi→rx_rings[i]를 가르키는 포인터에서 수행하므로 결과적으로 vsi 의 rx_rings 배열의 rx_ring들을 하나하나 설정하게 됨.