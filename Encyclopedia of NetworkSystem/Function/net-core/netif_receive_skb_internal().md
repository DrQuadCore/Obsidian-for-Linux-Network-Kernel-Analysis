---
Parameter:
  - sk_buff
Return: int
Location: /net/core/dev.c
---
```c
static int netif_receive_skb_internal(struct sk_buff *skb)
{
	int ret;

	net_timestamp_check(READ_ONCE(net_hotdata.tstamp_prequeue), skb);

	if (skb_defer_rx_timestamp(skb))
		return NET_RX_SUCCESS;

	rcu_read_lock();
#ifdef CONFIG_RPS
	if (static_branch_unlikely(&rps_needed)) {
		struct rps_dev_flow voidflow, *rflow = &voidflow;
		int cpu = get_rps_cpu(skb->dev, skb, &rflow);

		if (cpu >= 0) {
			ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);
			rcu_read_unlock();
			return ret;
		}
	}
#endif
	ret = __netif_receive_skb(skb);
	rcu_read_unlock();
	return ret;
}
```

[[Encyclopedia of NetworkSystem/Function/net-core/get_rps_cpu()]]
[[enqueue_to_backlog()]]
[[__netif_receive_skb()]]

rps를 사용하는 경우, skb를 보내야하는 cpu를 찾고 존재할 경우, enqueue_to_backlog() 함수를 실행
사용하지 않는 경우에는 `__netif_receive_skb()` 실행한다.
