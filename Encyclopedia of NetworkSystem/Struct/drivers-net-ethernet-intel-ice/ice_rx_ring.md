---
Location: /drivers/net/ethernet/intel/ice/ice_txrx.h
sticker: ""
---

```c title=ice_rx_ring
/* descriptor ring, associated with a VSI */
struct ice_rx_ring {
	/* CL1 - 1st cacheline starts here */
	void *desc;			/* Descriptor ring memory */
	struct device *dev;		/* Used for DMA mapping */
	struct net_device *netdev;	/* netdev ring maps to */
	struct ice_vsi *vsi;		/* Backreference to associated VSI */
	struct ice_q_vector *q_vector;	/* Backreference to associated vector */
	u8 __iomem *tail;
	u16 q_index;			/* Queue number of ring */

	u16 count;			/* Number of descriptors */
	u16 reg_idx;			/* HW register index of the ring */
	u16 next_to_alloc;

	union {
		struct ice_rx_buf *rx_buf;
		struct xdp_buff **xdp_buf;
	};
	/* CL2 - 2nd cacheline starts here */
	union {
		struct ice_xdp_buff xdp_ext;
		struct xdp_buff xdp;
	};
	/* CL3 - 3rd cacheline starts here */
	union {
		struct ice_pkt_ctx pkt_ctx;
		struct {
			u64 cached_phctime;
			__be16 vlan_proto;
		};
	};
	struct bpf_prog *xdp_prog;
	u16 rx_offset;

	/* used in interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;
	u16 first_desc;

	/* stats structs */
	struct ice_ring_stats *ring_stats;

	struct rcu_head rcu;		/* to avoid race on free */
	/* CL4 - 4th cacheline starts here */
	struct ice_channel *ch;
	struct ice_tx_ring *xdp_ring;
	struct ice_rx_ring *next;	/* pointer to next ring in q_vector */
	struct xsk_buff_pool *xsk_pool;
	u32 nr_frags;
	dma_addr_t dma;			/* physical address of ring */
	u16 rx_buf_len;
	u8 dcb_tc;			/* Traffic class of ring */
	u8 ptp_rx;
#define ICE_RX_FLAGS_RING_BUILD_SKB	BIT(1)
#define ICE_RX_FLAGS_CRC_STRIP_DIS	BIT(2)
	u8 flags;
	/* CL5 - 5th cacheline starts here */
	struct xdp_rxq_info xdp_rxq;
} ____cacheline_internodealigned_in_smp;
```
→ next 포인터는 다음 ice_rx_ring을 가르키는 포인터임. 고로 linked list 형태