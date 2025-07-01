---
Parameter:
  - ice_rx_ring
Return: bool
Location: /drivers/net/ethernet/intel/ice/ice_txrx.h
---

```c title=ice_ring_uses_build_skb()
static inline bool ice_ring_uses_build_skb(struct ice_rx_ring *ring)
{
	return !!(ring->flags & ICE_RX_FLAGS_RING_BUILD_SKB);
}
```

> 간단한 인라인 함수이다. rx_ring의 flag에서 ICE_RX_FLAGS_RINGS_BUILD_SKB가 켜져 있는지만 확인하는 함수이다.