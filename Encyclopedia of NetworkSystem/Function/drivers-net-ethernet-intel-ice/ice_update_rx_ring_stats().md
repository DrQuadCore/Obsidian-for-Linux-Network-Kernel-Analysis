---
Parameter:
  - ice_rx_ring
  - u64
Return: void
Location: /drivers/net/ethernet/intel/ice/ice_lib.c
---

```c title=ice_update_rx_ring_stats()
/**
 * ice_update_rx_ring_stats - Update Rx ring specific counters
 * @rx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void ice_update_rx_ring_stats(struct ice_rx_ring *rx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&rx_ring->ring_stats->syncp);
	ice_update_ring_stats(&rx_ring->ring_stats->stats, pkts, bytes);
	u64_stats_update_end(&rx_ring->ring_stats->syncp);
}
```

> rx ring의 상태를 업데이트하는 코드