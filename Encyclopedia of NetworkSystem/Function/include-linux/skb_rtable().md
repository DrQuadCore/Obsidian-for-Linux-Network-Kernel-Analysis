---
Parameter:
  - sk_buff
Return: rtable
Location: /include/linux/skbuff.h
---
```c
/**
 * skb_rtable - Returns the skb &rtable
 * @skb: buffer
 */
static inline struct rtable *skb_rtable(const struct sk_buff *skb)
{
	return (struct rtable *)skb_dst(skb); // [[skb_dst()]]
}
```

---

skb_dst()에서 dst_entry를 리턴하면 이를 다시 rtable로 타입캐스팅을 진행한다. IPv4에서는 rtable로, IPv6에서는 rt6_info을 통해 라우팅에 필요한 추가적인 세부 정보를 저장해야 하기 때문이다. 

```c
struct rtable {
	struct dst_entry	dst;

	int			rt_genid;
	unsigned int		rt_flags;
	__u16			rt_type;
	__u8			rt_is_input;
	__u8			rt_uses_gateway;

	int			rt_iif;

	u8			rt_gw_family;
	/* Info on neighbour */
	union {
		__be32		rt_gw4;
		struct in6_addr	rt_gw6;
	};

	/* Miscellaneous cached information */
	u32			rt_mtu_locked:1,
				rt_pmtu:31;
};

```