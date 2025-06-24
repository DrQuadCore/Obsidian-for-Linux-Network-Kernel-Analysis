---
Parameter:
  - ice_tx_ring
  - int
Return: bool
Location: /drivers/net/ethernet/intel/ice/ice_txrx.c
---

```c title=ice_clean_tx_irq()
/**
 * ice_clean_tx_irq - Reclaim resources after transmit completes
 * @tx_ring: Tx ring to clean
 * @napi_budget: Used to determine if we are in netpoll
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 */
static bool ice_clean_tx_irq(struct ice_tx_ring *tx_ring, int napi_budget)
{
	unsigned int total_bytes = 0, total_pkts = 0;
	unsigned int budget = ICE_DFLT_IRQ_WORK;
	struct ice_vsi *vsi = tx_ring->vsi;
	s16 i = tx_ring->next_to_clean;
	struct ice_tx_desc *tx_desc;
	struct ice_tx_buf *tx_buf;

	/* get the bql data ready */
	netdev_txq_bql_complete_prefetchw(txring_txq(tx_ring));

	tx_buf = &tx_ring->tx_buf[i];
	tx_desc = ICE_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	prefetch(&vsi->state);

	do {
		struct ice_tx_desc *eop_desc = tx_buf->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* follow the guidelines of other drivers */
		prefetchw(&tx_buf->skb->users);

		smp_rmb();	/* prevent any other reads prior to eop_desc */

		ice_trace(clean_tx_irq, tx_ring, tx_desc, tx_buf);
		/* if the descriptor isn't done, no work yet to do */
		if (!(eop_desc->cmd_type_offset_bsz &
		      cpu_to_le64(ICE_TX_DESC_DTYPE_DESC_DONE)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_pkts += tx_buf->gso_segs;

		/* free the skb */
		napi_consume_skb(tx_buf->skb, napi_budget);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len),
				 DMA_TO_DEVICE);

		/* clear tx_buf data */
		tx_buf->type = ICE_TX_BUF_EMPTY;
		dma_unmap_len_set(tx_buf, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			ice_trace(clean_tx_irq_unmap, tx_ring, tx_desc, tx_buf);
			tx_buf++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buf = tx_ring->tx_buf;
				tx_desc = ICE_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buf, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buf, dma),
					       dma_unmap_len(tx_buf, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buf, len, 0);
			}
		}
		ice_trace(clean_tx_irq_unmap_eop, tx_ring, tx_desc, tx_buf);

		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buf = tx_ring->tx_buf;
			tx_desc = ICE_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;

	ice_update_tx_ring_stats(tx_ring, total_pkts, total_bytes);
	netdev_tx_completed_queue(txring_txq(tx_ring), total_pkts, total_bytes);

#define TX_WAKE_THRESHOLD ((s16)(DESC_NEEDED * 2))
	if (unlikely(total_pkts && netif_carrier_ok(tx_ring->netdev) &&
		     (ICE_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (netif_tx_queue_stopped(txring_txq(tx_ring)) &&
		    !test_bit(ICE_VSI_DOWN, vsi->state)) {
			netif_tx_wake_queue(txring_txq(tx_ring));
			++tx_ring->ring_stats->tx_stats.restart_q;
		}
	}

	return !!budget;
}
```
