---
Location: /include/net/netdev_rx_queue.h
---
```c
/* This structure contains an instance of an RX queue. */
struct netdev_rx_queue {
	struct xdp_rxq_info		xdp_rxq;
#ifdef CONFIG_RPS
	struct rps_map __rcu		*rps_map;
	struct rps_dev_flow_table __rcu	*rps_flow_table;
#endif
	struct kobject			kobj;
	struct net_device		*dev;
	netdevice_tracker		dev_tracker;

#ifdef CONFIG_XDP_SOCKETS
	struct xsk_buff_pool            *pool;
#endif
	/* NAPI instance for the queue
	 * Readers and writers must hold RTNL
	 */
	struct napi_struct		*napi;
} ____cacheline_aligned_in_smp;
```