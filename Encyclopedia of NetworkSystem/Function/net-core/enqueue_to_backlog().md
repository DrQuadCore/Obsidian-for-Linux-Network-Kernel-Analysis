---
Parameter:
  - sk_buff
  - int
  - unsigned int
Return: int
Location: /net/core/dev.c
---

```c
static int enqueue_to_backlog(struct sk_buff *skb, int cpu,
			      unsigned int *qtail)
{
	enum skb_drop_reason reason;
	struct softnet_data *sd;
	unsigned long flags;
	unsigned int qlen;

	reason = SKB_DROP_REASON_NOT_SPECIFIED;
	sd = &per_cpu(softnet_data, cpu);
2
	rps_lock_irqsave(sd, &flags);
	if (!netif_running(skb->dev))
		goto drop;
	qlen = skb_queue_len(&sd->input_pkt_queue);
	if (qlen <= READ_ONCE(net_hotdata.max_backlog) &&
	    !skb_flow_limit(skb, qlen)) {
		if (qlen) {
enqueue:
			__skb_queue_tail(&sd->input_pkt_queue, skb);
			input_queue_tail_incr_save(sd, qtail);
			rps_unlock_irq_restore(sd, &flags);
			return NET_RX_SUCCESS;
		}

		/* Schedule NAPI for backlog device
		 * We can use non atomic operation since we own the queue lock
		 */
		if (!__test_and_set_bit(NAPI_STATE_SCHED, &sd->backlog.state))
			napi_schedule_rps(sd);
		goto enqueue;
	}
	reason = SKB_DROP_REASON_CPU_BACKLOG;

drop:
	sd->dropped++;
	rps_unlock_irq_restore(sd, &flags);

	dev_core_stats_rx_dropped_inc(skb->dev);
	kfree_skb_reason(skb, reason);
	return NET_RX_DROP;
}
```

[[napi_schedule_rps()]]

enqueue_to_backlog()가 해당 skb가 처리되어야 할 cpu로 보내는 주요 역할을 하는 함수이다. enqueue_to_backlog()에서는 가야할 cpu의 sd→input_pck_queue에 tail에 덧붙이는 작업만 하여, 적절한 cpu에서 처리 될 수 있도록 한다. 그런데 만약, 그 cpu의 input_pck_queue가 비어있는 상황이면, __napi_schedule_rps()를 실행하여, 해당 cpu의 input_pck_queue를 새롭게 스케줄링 한다.

이 함수에서부터의 주요 관계도 그림은 아래 링크와 같다. 
[[RPS-IPI 관계도]]