---
Location: /drivers/net/ethernet/intel/ice/ice_txrx.h
sticker: ""
---

```c title=ice_tx_ring
struct ice_tx_ring {
	/* CL1 - 1st cacheline starts here */
	struct ice_tx_ring *next;	/* pointer to next ring in q_vector */
	void *desc;			/* Descriptor ring memory */
	struct device *dev;		/* Used for DMA mapping */
	u8 __iomem *tail;
	struct ice_tx_buf *tx_buf;
	struct ice_q_vector *q_vector;	/* Backreference to associated vector */
	struct net_device *netdev;	/* netdev ring maps to */
	struct ice_vsi *vsi;		/* Backreference to associated VSI */
	/* CL2 - 2nd cacheline starts here */
	dma_addr_t dma;			/* physical address of ring */
	struct xsk_buff_pool *xsk_pool;
	u16 next_to_use;
	u16 next_to_clean;
	u16 q_handle;			/* Queue handle per TC */
	u16 reg_idx;			/* HW register index of the ring */
	u16 count;			/* Number of descriptors */
	u16 q_index;			/* Queue number of ring */
	u16 xdp_tx_active;
	/* stats structs */
	struct ice_ring_stats *ring_stats;
	/* CL3 - 3rd cacheline starts here */
	struct rcu_head rcu;		/* to avoid race on free */
	DECLARE_BITMAP(xps_state, ICE_TX_NBITS);	/* XPS Config State */
	struct ice_channel *ch;
	struct ice_ptp_tx *tx_tstamps;
	spinlock_t tx_lock;
	u32 txq_teid;			/* Added Tx queue TEID */
	/* CL4 - 4th cacheline starts here */
#define ICE_TX_FLAGS_RING_XDP		BIT(0)
#define ICE_TX_FLAGS_RING_VLAN_L2TAG1	BIT(1)
#define ICE_TX_FLAGS_RING_VLAN_L2TAG2	BIT(2)
	u8 flags;
	u8 dcb_tc;			/* Traffic class of ring */
} ____cacheline_internodealigned_in_smp;
```
→ next 포인터는 다음 ice_tx_ring을 가르키는 포인터임. 고로 linked list 형태