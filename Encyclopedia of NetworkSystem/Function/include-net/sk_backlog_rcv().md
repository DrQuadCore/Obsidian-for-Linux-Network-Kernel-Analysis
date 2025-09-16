---
Parameter:
- sock *
- sk_buff *
Return:
- int
Location:
- /include/net/sock.h
---
```c title=sk_backlog_rcv()
static inline int sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (sk_memalloc_socks() && skb_pfmemalloc(skb))
		return __sk_backlog_rcv(sk, skb);

	return INDIRECT_CALL_INET(sk->sk_backlog_rcv,
				  tcp_v6_do_rcv,
				  tcp_v4_do_rcv,
				  sk, skb);
}
```

- 메모리가 부족해 특별한 소켓이 할당되었고, `sk_buff`가 page frame memory allocator에 의해 메모리가 할당되었을 때는 `__sk_backlog_rcv()` 함수로 메모리 회수를 비활성화하고 다음 단계로 넘어감
- 일반적인 경우는 프로토콜에 따라 패킷 처리하는 함수 실행(백로그에 다시 넣지 않음)

```c title=__sk_backlog_rcv()
/**
 * skb_pfmemalloc - Test if the skb was allocated from PFMEMALLOC reserves
 * @skb: buffer
 */
static inline bool skb_pfmemalloc(const struct sk_buff *skb)
{
	return unlikely(skb->pfmemalloc);
}

#ifdef CONFIG_NET
DECLARE_STATIC_KEY_FALSE(memalloc_socks_key);
static inline int sk_memalloc_socks(void)
{
	return static_branch_unlikely(&memalloc_socks_key);
}

int __sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	int ret;
	unsigned int noreclaim_flag;

	/* these should have been dropped before queueing */
	BUG_ON(!sock_flag(sk, SOCK_MEMALLOC));

	noreclaim_flag = memalloc_noreclaim_save();
	ret = INDIRECT_CALL_INET(sk->sk_backlog_rcv,
				 tcp_v6_do_rcv,
				 tcp_v4_do_rcv,
				 sk, skb);
	memalloc_noreclaim_restore(noreclaim_flag);

	return ret;
}
EXPORT_SYMBOL(__sk_backlog_rcv);
```



[[tcp_v4_do_rcv()]]