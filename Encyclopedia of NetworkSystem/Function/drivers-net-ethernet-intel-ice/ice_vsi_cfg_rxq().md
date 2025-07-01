---
Parameter:
  - ice_rx_ring
Return: int
Location: /drivers/net/ethernet/intel/ice/ice_base.c
---

```c title=ice_vsi_cfg_rxq()
/**
 * ice_vsi_cfg_rxq - Configure an Rx queue
 * @ring: the ring being configured
 *
 * Return 0 on success and a negative value on error.
 */
static int ice_vsi_cfg_rxq(struct ice_rx_ring *ring)
{
	struct device *dev = ice_pf_to_dev(ring->vsi->back);
	u32 num_bufs = ICE_RX_DESC_UNUSED(ring);
	int err;

	ring->rx_buf_len = ring->vsi->rx_buf_len;

	if (ring->vsi->type == ICE_VSI_PF) {
		if (!xdp_rxq_info_is_reg(&ring->xdp_rxq)) {
			err = __xdp_rxq_info_reg(&ring->xdp_rxq, ring->netdev,
						 ring->q_index,
						 ring->q_vector->napi.napi_id,
						 ring->rx_buf_len);
			if (err)
				return err;
		}

		ring->xsk_pool = ice_xsk_pool(ring);
		if (ring->xsk_pool) {
			xdp_rxq_info_unreg(&ring->xdp_rxq);

			ring->rx_buf_len =
				xsk_pool_get_rx_frame_size(ring->xsk_pool);
			err = __xdp_rxq_info_reg(&ring->xdp_rxq, ring->netdev,
						 ring->q_index,
						 ring->q_vector->napi.napi_id,
						 ring->rx_buf_len);
			if (err)
				return err;
			err = xdp_rxq_info_reg_mem_model(&ring->xdp_rxq,
							 MEM_TYPE_XSK_BUFF_POOL,
							 NULL);
			if (err)
				return err;
			xsk_pool_set_rxq_info(ring->xsk_pool, &ring->xdp_rxq);
			ice_xsk_pool_fill_cb(ring);

			dev_info(dev, "Registered XDP mem model MEM_TYPE_XSK_BUFF_POOL on Rx ring %d\n",
				 ring->q_index);
		} else {
			if (!xdp_rxq_info_is_reg(&ring->xdp_rxq)) {
				err = __xdp_rxq_info_reg(&ring->xdp_rxq, ring->netdev,
							 ring->q_index,
							 ring->q_vector->napi.napi_id,
							 ring->rx_buf_len);
				if (err)
					return err;
			}

			err = xdp_rxq_info_reg_mem_model(&ring->xdp_rxq,
							 MEM_TYPE_PAGE_SHARED,
							 NULL);
			if (err)
				return err;
		}
	}

	xdp_init_buff(&ring->xdp, ice_rx_pg_size(ring) / 2, &ring->xdp_rxq);
	ring->xdp.data = NULL;
	ring->xdp_ext.pkt_ctx = &ring->pkt_ctx;
	err = ice_setup_rx_ctx(ring);
	if (err) {
		dev_err(dev, "ice_setup_rx_ctx failed for RxQ %d, err %d\n",
			ring->q_index, err);
		return err;
	}

	if (ring->xsk_pool) {
		bool ok;

		if (!xsk_buff_can_alloc(ring->xsk_pool, num_bufs)) {
			dev_warn(dev, "XSK buffer pool does not provide enough addresses to fill %d buffers on Rx ring %d\n",
				 num_bufs, ring->q_index);
			dev_warn(dev, "Change Rx ring/fill queue size to avoid performance issues\n");

			return 0;
		}

		ok = ice_alloc_rx_bufs_zc(ring, num_bufs);
		if (!ok) {
			u16 pf_q = ring->vsi->rxq_map[ring->q_index];

			dev_info(dev, "Failed to allocate some buffers on XSK buffer pool enabled Rx ring %d (pf_q %d)\n",
				 ring->q_index, pf_q);
		}

		return 0;
	}

	ice_alloc_rx_bufs(ring, num_bufs);

	return 0;
}
```
