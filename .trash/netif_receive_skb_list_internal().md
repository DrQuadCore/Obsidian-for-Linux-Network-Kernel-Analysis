---
Return:
  - void
Location: /net/core/dev.c
parameter:
  - list_head
---
```  c title=netif_receive_skb_list_internal코드

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

  

if (cpu >= 0) {

/* Will be handled, remove from list */

skb_list_del_init(skb);

enqueue_to_backlog(skb, cpu, &rflow->last_qtail);

}

}

}

#endif

__netif_receive_skb_list(head);

rcu_read_unlock();

}
```

>새로운 서브리스트를 생성하고, 주어진 `napi->rx_list`를 돌면서 해당 `skb`를 리스트에서 제거하고, `sublist`에 담게 된다.
>이 때, `list_splice_init(&sublsit, head)`를 하게 되면, 두 리스트를 합치고, 앞의 리스트를 초기화하게 된다.
>만약 `CONFIG_RPS`이라면, 각각의 리스트에 대하여 `enqueue_to_backlog()`함수를 실행하게 된다.
>그 이후 공통적으로, `__netif_receive_skb_list()`함수를 실행하게 된다.

[[__netif_receive_skb_list()]]
[[enqueue_to_backlog()]]
