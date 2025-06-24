---
Parameter:
  - list_head
Return: void
Location: /net/core/dev.c
---

```c title=netif_receive_skb_list_internal()
void netif_receive_skb_list_internal(struct list_head *head)
{
	struct sk_buff *skb, *next;
	struct list_head sublist;

	INIT_LIST_HEAD(&sublist);
	list_for_each_entry_safe(skb, next, head, list) {
		net_timestamp_check(READ_ONCE(net_hotdata.tstamp_prequeue),
				    skb);
		skb_list_del_init(skb);
		if (!skb_defer_rx_timestamp(skb))
			list_add_tail(&skb->list, &sublist);
	}
	list_splice_init(&sublist, head);

	rcu_read_lock();
#ifdef CONFIG_RPS
	if (static_branch_unlikely(&rps_needed)) {
		list_for_each_entry_safe(skb, next, head, list) {
			struct rps_dev_flow voidflow, *rflow = &voidflow;
			int cpu = get_rps_cpu(skb->dev, skb, &rflow);
					//[[get_rps_cpu()]]

			if (cpu >= 0) {
				**/* Will be handled, remove from list */**
				skb_list_del_init(skb);
				enqueue_to_backlog(skb, cpu, &rflow->last_qtail);
				// [[enqueue_to_backlog()]]
			}
		}
	}
#endif
	__netif_receive_skb_list(head); // [[Encyclopedia of NetworkSystem/Function/net-core/__netif_receive_skb_list().md|__netif_receive_skb_list()]]
	rcu_read_unlock();
}
```

[[__netif_receive_skb_list()|netif_receive_skb_list()]]
[[Encyclopedia of NetworkSystem/Function/net-core/enqueue_to_backlog()|enqueue_to_backlog()]]
[[Encyclopedia of NetworkSystem/Function/net-core/get_rps_cpu()]]

> timestamp를 확인하고 만약 rps가 설정되어 있을 경우 enqueue_to_backlog()를 통해 특정 cpu에 해당 flow를 할당하게 된다. 아니라면 `__netif_receive_skb_list(head)`를 호출하여 처리를 이어나가게 된다.

>새로운 서브리스트를 생성하고, 주어진 `napi->rx_list`를 돌면서 해당 `skb`를 리스트에서 제거하고, `sublist`에 담게 된다.
>이 때, `list_splice_init(&sublsit, head)`를 하게 되면, 두 리스트를 합치고, 앞의 리스트를 초기화하게 된다.
>만약 `CONFIG_RPS`이라면, 각각의 리스트에 대하여 `enqueue_to_backlog()`함수를 실행하게 된다.
>그 이후 공통적으로, `__netif_receive_skb_list()`함수를 실행하게 된다.

> get_rps_cpu()를 통해 rps를 해서 보낼 cpu 넘버를 int 형태로 반환할 것으로 추정 된다.