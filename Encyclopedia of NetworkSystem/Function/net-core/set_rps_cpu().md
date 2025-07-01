---
Return: rps_dev_flow *
Location: /net/core/dev.c
Parameter:
  - net_device
  - sk_buff
  - rps_dev_flow
  - u16
---
```c
static struct rps_dev_flow *
set_rps_cpu(struct net_device *dev, struct sk_buff *skb,
struct rps_dev_flow *rflow, u16 next_cpu)
{
	if (next_cpu < nr_cpu_ids) {
#ifdef CONFIG_RFS_ACCEL
		struct netdev_rx_queue *rxqueue;
		struct rps_dev_flow_table *flow_table;
		struct rps_dev_flow *old_rflow;
		u32 flow_id;
		u16 rxq_index;
		int rc;
		  
		/* Should we steer this flow to a different hardware queue? */
		if (!skb_rx_queue_recorded(skb) || !dev->rx_cpu_rmap ||
			!(dev->features & NETIF_F_NTUPLE))
			goto out;
		rxq_index = cpu_rmap_lookup_index(dev->rx_cpu_rmap, next_cpu);
		if (rxq_index == skb_get_rx_queue(skb))
			goto out;
		  
		rxqueue = dev->_rx + rxq_index;
		flow_table = rcu_dereference(rxqueue->rps_flow_table);
		if (!flow_table)
			goto out;
		flow_id = skb_get_hash(skb) & flow_table->mask;
		rc = dev->netdev_ops->ndo_rx_flow_steer(dev, skb,
							rxq_index, flow_id);
		if (rc < 0)
			goto out;
		old_rflow = rflow;
		rflow = &flow_table->flows[flow_id];
		rflow->filter = rc;
		if (old_rflow->filter == rflow->filter)
			old_rflow->filter = RPS_NO_FILTER;
		out:
#endif
		rflow->last_qtail =
			per_cpu(softnet_data, next_cpu).input_queue_head;
	}
  
	rflow->cpu = next_cpu;
	return rflow;
}
```

>![[Pasted image 20240816113600.png]]
>
>위의 참고자료의 한 문단이다.
>`rflow`는 해당 receive queue가 처리되고 있는 CPU를 가르키고 있는 것이다.
>위를 보면 알 수 있듯이, aRFS가 켜져있을 때 작동하는 코드들이 있다.
>그게 아니라면 `rflow->last_qtail`을 설정해주고, `rflow->cpu`들어온 `next_cpu`로 설정하게 된다.