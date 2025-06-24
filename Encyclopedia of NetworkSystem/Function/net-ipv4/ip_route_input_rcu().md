---
Parameter:
  - sk_buff
  - __be32
  - __be32_
  - u8
  - net_device
  - fib_result
Return: int
Location: /net/ipv4/route.c
---
```c
/* called with rcu_read_lock held */
static int ip_route_input_rcu(struct sk_buff *skb, __be32 daddr, __be32 saddr,
					u8 tos, struct net_device *dev, struct fib_result *res)
{
	/* Multicast recognition logic is moved from route cache to here.
	* The problem was that too many Ethernet cards have broken/missing
	* hardware multicast filters :-( As result the host on multicasting
	* network acquires a lot of useless route cache entries, sort of
	* SDR messages from all the world. Now we try to get rid of them.
	* Really, provided software IP multicast filter is organized
	* reasonably (at least, hashed), it does not result in a slowdown
	* comparing with route cache reject entries.
	* Note, that multicast routers are not affected, because
	* route cache entry is created eventually.
	*/
	if (ipv4_is_multicast(daddr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);
		int our = 0;
		int err = -EINVAL;
		  
		if (!in_dev)
			return err;
		our = ip_check_mc_rcu(in_dev, daddr, saddr,
						ip_hdr(skb)->protocol);
		  
		/* check l3 master if no match yet */
		if (!our && netif_is_l3_slave(dev)) {
			struct in_device *l3_in_dev;
		  
			l3_in_dev = __in_dev_get_rcu(skb->dev);
			if (l3_in_dev)
				our = qip_check_mc_rcu(l3_in_dev, daddr, saddr,
							ip_hdr(skb)->protocol);
	}
  
		if (our
#ifdef CONFIG_IP_MROUTE
			||
			(!ipv4_is_local_multicast(daddr) &&
			IN_DEV_MFORWARD(in_dev))
#endif
			) {
			err = ip_route_input_mc(skb, daddr, saddr,
						tos, dev, our);
		}
		return err;
	}
  
	return ip_route_input_slow(skb, daddr, saddr, tos, dev, res);
}
```

>멀티캐스트와 관련된 recognition이 여기에 많이 implement 되어있다. 기존에 다른 곳에 있었을 때는 하드웨어 레벨에서 멀티캐스트 필터가 고장나거나 잃어버리면서 제대로 작동하지 않는 경우가 굉장히 많았고, 불필요한 라우트 캐시 등을 생성하였다고 한다. 이러한 코드를 본 함수로 옮김으로써 어느정도 해결하였다고 한다. 
>
>따라서 if문을 통해 `ipv4_is_multicast()`함수를 조건으로 하여 멀티캐스트와 관련 된 처리들을 할 수 있게 코드가 작성되었고, 실질적인 라우팅은 `return`에 보면 `ip_route_input_slow()`함수를 실행하고 있는 것을 볼 수 있다.

[[ip_route_input_slow()]]