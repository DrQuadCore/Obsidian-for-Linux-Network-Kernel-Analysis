---
Location: /drivers/net/ethernet/intel/ice/ice_txrx.h
sticker: ""
---

```c title=ice_ring_container
struct ice_ring_container {
	/* head of linked-list of rings */
	union {
		struct ice_rx_ring *rx_ring; // [[Encyclopedia of NetworkSystem/Struct/drivers-net-ethernet-intel-ice/ice_rx_ring.md|ice_rx_ring]], [[Encyclopedia of NetworkSystem/Struct/drivers-net-ethernet-intel-ice/ice_tx_ring.md|ice_tx_ring]]
		struct ice_tx_ring *tx_ring; // 링을 가리키는 포인터
	};
	struct dim dim;		/* data for net_dim algorithm */
	u16 itr_idx;		/* index in the interrupt vector */
	/* this matches the maximum number of ITR bits, but in usec
	 * values, so it is shifted left one bit (bit zero is ignored)
	 */
	union {
		struct {
			u16 itr_setting:13;
			u16 itr_reserved:2;
			u16 itr_mode:1;
		};
		u16 itr_settings;
	};
	enum ice_container_type type;
};
```

[[Encyclopedia of NetworkSystem/Struct/drivers-net-ethernet-intel-ice/ice_rx_ring.md|ice_rx_ring]]
[[Encyclopedia of NetworkSystem/Struct/drivers-net-ethernet-intel-ice/ice_tx_ring.md|ice_tx_ring]]