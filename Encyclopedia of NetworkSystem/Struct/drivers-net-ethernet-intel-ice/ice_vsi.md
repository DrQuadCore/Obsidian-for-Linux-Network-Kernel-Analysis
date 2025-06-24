---
Location: /drivers/net/ethernet/intel/ice/ice.h
sticker: ""
---

```c title=ice_vsi
/* struct that defines a VSI, associated with a dev */
struct ice_vsi {
	struct net_device *netdev;
	struct ice_sw *vsw;		 /* switch this VSI is on */
	struct ice_pf *back;		 /* back pointer to PF */
	struct ice_port_info *port_info; /* back pointer to port_info */
	struct ice_rx_ring **rx_rings;	 /* Rx ring array */
	struct ice_tx_ring **tx_rings;	 /* Tx ring array */
	struct ice_q_vector **q_vectors; /* q_vector array */
	// [[Encyclopedia of NetworkSystem/Struct/drivers-net-ethernet-intel-ice/ice_q_vector.md|ice_q_vector]]

	irqreturn_t (*irq_handler)(int irq, void *data);

	u64 tx_linearize;
	DECLARE_BITMAP(state, ICE_VSI_STATE_NBITS);
	unsigned int current_netdev_flags;
	u32 tx_restart;
	u32 tx_busy;
	u32 rx_buf_failed;
	u32 rx_page_failed;
	u16 num_q_vectors;
	/* tell if only dynamic irq allocation is allowed */
	bool irq_dyn_alloc;

	enum ice_vsi_type type;
	u16 vsi_num;			/* HW (absolute) index of this VSI */
	u16 idx;			/* software index in pf->vsi[] */

	struct ice_vf *vf;		/* VF associated with this VSI */

	u16 num_gfltr;
	u16 num_bfltr;

	/* RSS config */
	u16 rss_table_size;	/* HW RSS table size */
	u16 rss_size;		/* Allocated RSS queues */
	u8 rss_hfunc;		/* User configured hash type */
	u8 *rss_hkey_user;	/* User configured hash keys */
	u8 *rss_lut_user;	/* User configured lookup table entries */
	u8 rss_lut_type;	/* used to configure Get/Set RSS LUT AQ call */

	/* aRFS members only allocated for the PF VSI */
#define ICE_MAX_ARFS_LIST	1024
#define ICE_ARFS_LST_MASK	(ICE_MAX_ARFS_LIST - 1)
	struct hlist_head *arfs_fltr_list;
	struct ice_arfs_active_fltr_cntrs *arfs_fltr_cntrs;
	spinlock_t arfs_lock;	/* protects aRFS hash table and filter state */
	atomic_t *arfs_last_fltr_id;

	u16 max_frame;
	u16 rx_buf_len;

	struct ice_aqc_vsi_props info;	 /* VSI properties */
	struct ice_vsi_vlan_info vlan_info;	/* vlan config to be restored */

	/* VSI stats */
	struct rtnl_link_stats64 net_stats;
	struct rtnl_link_stats64 net_stats_prev;
	struct ice_eth_stats eth_stats;
	struct ice_eth_stats eth_stats_prev;

	struct list_head tmp_sync_list;		/* MAC filters to be synced */
	struct list_head tmp_unsync_list;	/* MAC filters to be unsynced */

	u8 irqs_ready:1;
	u8 current_isup:1;		 /* Sync 'link up' logging */
	u8 stat_offsets_loaded:1;
	struct ice_vsi_vlan_ops inner_vlan_ops;
	struct ice_vsi_vlan_ops outer_vlan_ops;
	u16 num_vlan;

	/* queue information */
	u8 tx_mapping_mode;		 /* ICE_MAP_MODE_[CONTIG|SCATTER] */
	u8 rx_mapping_mode;		 /* ICE_MAP_MODE_[CONTIG|SCATTER] */
	u16 *txq_map;			 /* index in pf->avail_txqs */
	u16 *rxq_map;			 /* index in pf->avail_rxqs */
	u16 alloc_txq;			 /* Allocated Tx queues */
	u16 num_txq;			 /* Used Tx queues */
	u16 alloc_rxq;			 /* Allocated Rx queues */
	u16 num_rxq;			 /* Used Rx queues */
	u16 req_txq;			 /* User requested Tx queues */
	u16 req_rxq;			 /* User requested Rx queues */
	u16 num_rx_desc;
	u16 num_tx_desc;
	u16 qset_handle[ICE_MAX_TRAFFIC_CLASS];
	struct ice_tc_cfg tc_cfg;
	struct bpf_prog *xdp_prog;
	struct ice_tx_ring **xdp_rings;	 /* XDP ring array */
	unsigned long *af_xdp_zc_qps;	 /* tracks AF_XDP ZC enabled qps */
	u16 num_xdp_txq;		 /* Used XDP queues */
	u8 xdp_mapping_mode;		 /* ICE_MAP_MODE_[CONTIG|SCATTER] */

	struct net_device **target_netdevs;

	struct tc_mqprio_qopt_offload mqprio_qopt; /* queue parameters */

	/* Channel Specific Fields */
	struct ice_vsi *tc_map_vsi[ICE_CHNL_MAX_TC];
	u16 cnt_q_avail;
	u16 next_base_q;	/* next queue to be used for channel setup */
	struct list_head ch_list;
	u16 num_chnl_rxq;
	u16 num_chnl_txq;
	u16 ch_rss_size;
	u16 num_chnl_fltr;
	/* store away rss size info before configuring ADQ channels so that,
	 * it can be used after tc-qdisc delete, to get back RSS setting as
	 * they were before
	 */
	u16 orig_rss_size;
	/* this keeps tracks of all enabled TC with and without DCB
	 * and inclusive of ADQ, vsi->mqprio_opt keeps track of queue
	 * information
	 */
	u8 all_numtc;
	u16 all_enatc;

	/* store away TC info, to be used for rebuild logic */
	u8 old_numtc;
	u16 old_ena_tc;

	struct ice_channel *ch;

	/* setup back reference, to which aggregator node this VSI
	 * corresponds to
	 */
	struct ice_agg_node *agg_node;
} ____cacheline_internodealigned_in_smp;
```

[[Encyclopedia of NetworkSystem/Struct/drivers-net-ethernet-intel-ice/ice_q_vector.md|ice_q_vector]]

