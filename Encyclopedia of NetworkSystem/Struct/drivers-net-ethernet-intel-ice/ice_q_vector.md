---
Location: /drivers/net/ethernet/intel/ice/ice.h
---

```c title=ice_q_vector
/* struct that defines an interrupt vector */
struct ice_q_vector {
	struct ice_vsi *vsi;

	u16 v_idx;			/* index in the vsi->q_vector array. */
	u16 reg_idx;
	u8 num_ring_rx;			/* total number of Rx rings in vector */
	u8 num_ring_tx;			/* total number of Tx rings in vector */
	u8 wb_on_itr:1;			/* if true, WB on ITR is enabled */
	/* in usecs, need to use ice_intrl_to_usecs_reg() before writing this
	 * value to the device
	 */
	u8 intrl;

	struct napi_struct napi;

	struct ice_ring_container rx;
	struct ice_ring_container tx; //rx, tx 각각 있음.

	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;

	struct ice_channel *ch;

	char name[ICE_INT_NAME_STR_LEN];

	u16 total_events;	/* net_dim(): number of interrupts processed */
	struct msi_map irq; // [[Encyclopedia of NetworkSystem/Struct/include-linux/msi_map.md|msi_map]]
} ____cacheline_internodealigned_in_smp;
```

[[Encyclopedia of NetworkSystem/Struct/include-linux/msi_map.md|msi_map]]

각각의 q_vector는 rx, tx ring buffer의 그룹이다. 이러한 큐들의 그룹이 하나의 인터럽트에 할당 되게 되고, 이 때 묶음 큐는 linked list로 ice_ring_container에 포인터로 참조되어 있다.