```c title=tcp_transmit_skb()
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	return __tcp_transmit_skb(sk, skb, clone_it, gfp_mask,
				  tcp_sk(sk)->rcv_nxt);
}
```
- tcp의 receive sequence number를 추가하여 함수를 호출합니다.

[[__tcp_transmit_skb()]]