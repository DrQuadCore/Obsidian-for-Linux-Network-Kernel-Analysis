---
Parameter:
  - sock
  - sk_buff
Return: int
Location: /net/ipv4/tcp_ipv4.c
---

```c title=tcp_v4_do_rcv코드

/* The socket must have it's spinlock held when we get
* here, unless it is a TCP_LISTEN socket.
*
* We have a potential double-lock case here, so even when
* doing backlog processing we use the BH locking scheme.
* This is because we cannot sleep with the original spinlock
* held.
*/
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	enum skb_drop_reason reason;
	struct sock *rsk;

	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
		struct dst_entry *dst;

		dst = rcu_dereference_protected(sk->sk_rx_dst,
						lockdep_sock_is_held(sk));

		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
    
		if (dst) {
			if (sk->sk_rx_dst_ifindex != skb->skb_iif ||

			    !INDIRECT_CALL_1(dst->ops->check, ipv4_dst_check,
					     dst, 0)) {

				RCU_INIT_POINTER(sk->sk_rx_dst, NULL);
				dst_release(dst);
			}
		}
		tcp_rcv_established(sk, skb);
		return 0;
	}

	if (tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) {
		struct sock *nsk = tcp_v4_cookie_check(sk, skb);

		if (!nsk)
			return 0;
		if (nsk != sk) {
			reason = tcp_child_process(sk, nsk, skb);
			if (reason) {
				rsk = nsk;
				goto reset;
			}
			return 0;
		}
	} else
  
		sock_rps_save_rxhash(sk, skb);

	reason = tcp_rcv_state_process(sk, skb);
	if (reason) {
		rsk = sk;
		goto reset;
	}
	return 0;

reset:
	tcp_v4_send_reset(rsk, skb);
discard:
	kfree_skb_reason(skb, reason);
	/* Be careful here. If this function gets more complicated and

	 * gcc suffers from register pressure on the x86, sk (in %ebx)
	 * might be destroyed here. This current version compiles correctly,
	 * but you have been warned.
	 */
	return 0;

csum_err:
	reason = SKB_DROP_REASON_TCP_CSUM;
	trace_tcp_bad_csum(skb);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
	goto discard;
}
```

>우선 소켓의 상태가 `TCP_ESTABLISHED`인지 확인한다. 이 경로는 Fast path이다.
>`sk->sk_rx_dst`에서 `dst`를 불러오게 되는데, INDIRECT_CALL_1 등을 통해 `ipv4_dst_check()`함수들을 실행하여 조건을 확인하고, 만약 유효하지 않은 `dst_entry`라면  `dst_release`를 실행하여 `dst_entry`구조체를 release한다.
>그후 `tcp_rcv_established()`함수를 실행하여 패킷 처리작업을 이어가고, 0을 반환한다.
>
>소켓의 상태가 `TCP_ESTABLISHED`가 아닌 경우에는 체크썸을 확인하고, 소켓이 `TCP_LISTEN` 상태인지 확인하게 된다.
>만약 그렇다면, `nsk`를 선언하여 작업을 이어나가게 된다. 만약 이 `nsk`가 `sk`와 다르다면, `tcp_child_process()` 함수를 호출하고, `reason`에 결과값을 반환하게 된다. 만약 reason이 있다면, `reset` 라벨로 가게 되고, 아니라면 그대로 종료된다.
>
>`TCP_LISTEN`이 아니라면 `sock_rps_save_rxhash()`함수를 실행한다.
>
>그다음으로 `tcp_rcv_state_process()`함수의 반환값을 `reason`으로 받아서 `reset` 라벨로 가거나 아니라면 종료한다. 여기는 `ESTABLISHED`상태와 `TIME_WAIT` 상태가 아닌 모든 소켓들이 처리되는 함수이다.
>
>`reset`라벨은 `tcp_v4_send_reset()`함수를 실행시킨다. -> `RST` flag가 세팅되어 있는 패킷을 전송하게 된다.
>`discard`라벨은 `kfree_skb_reason()`함수를 실행 시킨다.
> 이후 0을 반환하게 된다.

---
1. socket state가 TCP_ESTABLISHED 경우, `tcp_rcv_established()`를 호출하여 처리한다.
2. state가 TCP_LISTEN 경우, cookie_check 이 후 `tcp_child_process()`를 호출하여 처리한다.
3. 그 외에는 `tcp_rcv_state_process()`를 호출하여 처리한다.

[[sock_rps_save_rxhash()]]
[[김기수/산협 프로젝트 2/백서 제작용/tcp_child_process()|tcp_child_process()]]
[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_rcv_established()]]
[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_rcv_state_process()|tcp_rcv_state_process()]]
[[tcp_v4_send_reset()]]
