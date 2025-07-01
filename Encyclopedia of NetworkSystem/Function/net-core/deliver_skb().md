---
Parameter:
  - net_device
  - packet_type
  - sk_buff
Return: int
Location: /net/core/dev.c
---

```c title=deliver_skb
static inline int deliver_skb(struct sk_buff *skb,
				  struct packet_type *pt_prev,
				  struct net_device *orig_dev)
{
	if (unlikely(skb_orphan_frags_rx(skb, GFP_ATOMIC)))
		return -ENOMEM;
	refcount_inc(&skb->users);
	return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}
```

>`skb_orphan_frags_rx()`함수의 리턴값이 true이면 `-ENOMEM`을 리턴한다. 그게 아니라면 `refcount_inc(&skb->users)`를 통해 참조 카운터를 증가시키고, `pt_prev->func()`를 통해 해당하는 패킷타입에 알맞은 처리 함수를 실행해주게 된다.

>함수 포인터 매핑부터 살펴보자면, 우선 net/ipv4/af_inet.c에서 inet_init()함수에서 `dev_add_pack(&ip_packet_type)`함수를 호출한다. 이는 네트워크 스택에다가 다루어져야 할 패킷 타입들에 대한 handler_function을 매핑하는 함수이다. `net_hotdata`혹은 받은 `packet_type`이 가르키고 있는 `net_dev`의 `ptype_all` 리스트에 이를 추가하게 된다. 여기서는 `dev`에 해당하는 포인터가 위의 `ip_packet_type`을 선언하고 초기화하는 과정에서 `NULL`값으로 셋팅 될 것이므로, `net_hotdata->ptype_all`에 저장 될 것이다. 이 때 `func`에 매핑되는 함수는 `ip_rcv`이고, `list_func`에 매핑되는 함수는`ip_list_rcv`이다.

[[ip_rcv()]]
