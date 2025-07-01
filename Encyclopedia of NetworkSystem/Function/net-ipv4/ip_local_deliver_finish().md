---
Parameter:
  - net
  - sock
  - sk_buff
Return: int
Location: /net/ipv4/ip_input.c
---
2
```c title=ip_local_deliver_finish코드
static int ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	skb_clear_delivery_time(skb);
	__skb_pull(skb, skb_network_header_len(skb));
	  
	rcu_read_lock();
	ip_protocol_deliver_rcu(net, skb, ip_hdr(skb)->protocol);
	rcu_read_unlock();
	  
	return 0;
}
```

>L3 헤더를 지우고 상위 L4 스택으로 넘기고 있다.

[[ip_protocol_deliver_rcu()]]
