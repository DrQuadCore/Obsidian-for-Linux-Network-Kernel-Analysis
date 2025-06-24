---
Parameter:
  - sk_buff
  - __be32
  - __be32_
  - u8
  - net_device
Return: int
Location: /net/ipv4/route.c
---
```c
int ip_route_input_noref(struct sk_buff *skb, __be32 daddr, __be32 saddr,
			u8 tos, struct net_device *dev)
{
	struct fib_result res;
	int err;
	  
	tos &= IPTOS_RT_MASK;
	rcu_read_lock();
	err = ip_route_input_rcu(skb, daddr, saddr, tos, dev, &res);
	rcu_read_unlock();
	  
	return err;
}
```

>rcu 락을 획득하고, `ip_route_input_rcu()`함수를 호출하게 된다. 단순히 RCU를 획득하기 위한wrapper 함수이다.

[[ip_route_input_rcu()]]