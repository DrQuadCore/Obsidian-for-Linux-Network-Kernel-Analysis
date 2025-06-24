---
Location: /include/linux/netdevice.h
sticker: ""
---

```c title=napi_struct
/*
 * Structure for NAPI scheduling similar to tasklet but with weighting
 */
struct napi_struct {
	/* The poll_list must only be managed by the entity which
	 * changes the state of the NAPI_STATE_SCHED bit.  This means
	 * whoever atomically sets that bit can add this napi_struct
	 * to the per-CPU poll_list, and whoever clears that bit
	 * can remove from the list right before clearing the bit.
	 */
	struct list_head	poll_list;

	unsigned long		state;
	int			weight;
	int			defer_hard_irqs_count;
	unsigned long		gro_bitmask;
	int			(*poll)(struct napi_struct *, int);
#ifdef CONFIG_NETPOLL
	/* CPU actively polling if netpoll is configured */
	int			poll_owner;
#endif
	/* CPU on which NAPI has been scheduled for processing */
	int			list_owner;
	struct net_device	*dev;
	struct gro_list		gro_hash[GRO_HASH_BUCKETS];
	struct sk_buff		*skb;
	struct list_head	rx_list; /* Pending GRO_NORMAL skbs */
	int			rx_count; /* length of rx_list */
	unsigned int		napi_id;
	struct hrtimer		timer;
	struct task_struct	*thread;
	/* control-path-only fields follow */
	struct list_head	dev_list;
	struct hlist_node	napi_hash_node;
	int			irq;
};
```
