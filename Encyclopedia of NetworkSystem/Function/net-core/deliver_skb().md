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

---
`skb_orphan_frags_rx()` 함수를 통해, 만약 skb frags가 userspace에 존재하는 page를 가리키고 있다면 이 frag들을 모두 kernel side로 copy 해 온다. 실패했을 경우에는 negative error code를 return 한다. [[SKB]]

```c
/* Frags must be orphaned, even if refcounted, if skb might loop to rx path */
static inline int skb_orphan_frags_rx(struct sk_buff *skb, gfp_t gfp_mask)
{
	if (likely(!skb_zcopy(skb)))
		return 0;
	return skb_copy_ubufs(skb, gfp_mask);
}

/**
 *	skb_copy_ubufs	-	copy userspace skb frags buffers to kernel
 *	@skb: the skb to modify
 *	@gfp_mask: allocation priority
 *
 *	This must be called on skb with SKBFL_ZEROCOPY_ENABLE.
 *	It will copy all frags into kernel and drop the reference
 *	to userspace pages.
 *
 *	If this function is called from an interrupt gfp_mask() must be
 *	%GFP_ATOMIC.
 *
 *	Returns 0 on success or a negative error code on failure
 *	to allocate kernel memory to copy to.
 */
int skb_copy_ubufs(struct sk_buff *skb, gfp_t gfp_mask)
```


그런 다음 `pt_prev->func()`를 통해 핸들러 함수를 부른다. packet의 Ethertype이 IPv4인 경우, ip_rcv로 연결된다. 
