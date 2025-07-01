---
Parameter:
  - ice_tx_ring
Return: bool
Location: /drivers/net/ethernet/intel/ice/ice_txrx.h
---

```c title=ice_ring_is_xdp()
static inline bool ice_ring_is_xdp(struct ice_tx_ring *ring)
{
	return !!(ring->flags & ICE_TX_FLAGS_RING_XDP);
}
```
