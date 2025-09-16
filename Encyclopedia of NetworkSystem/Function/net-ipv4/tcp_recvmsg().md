---
Parameter:
  - sock
  - msghdr
  - size_t
  - int
  - int_
Return: int
Location: /net/ipv4/tcp.c
---
```C
int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
		int *addr_len)
{
	int cmsg_flags = 0, ret;
	struct scm_timestamping_internal tss; // 타임스탬프 정보

	if (unlikely(flags & MSG_ERRQUEUE))
		return inet_recv_error(sk, msg, len, addr_len);

	if (sk_can_busy_loop(sk) &&
	    skb_queue_empty_lockless(&sk->sk_receive_queue) &&
	    sk->sk_state == TCP_ESTABLISHED)
		sk_busy_loop(sk, flags & MSG_DONTWAIT);

	lock_sock(sk);
	ret = tcp_recvmsg_locked(sk, msg, len, flags, &tss, &cmsg_flags);
	release_sock(sk);

	if ((cmsg_flags || msg->msg_get_inq) && ret >= 0) {
		if (cmsg_flags & TCP_CMSG_TS)
			tcp_recv_timestamp(msg, sk, &tss);
		if (msg->msg_get_inq) {
			msg->msg_inq = tcp_inq_hint(sk);
			if (cmsg_flags & TCP_CMSG_INQ)
				put_cmsg(msg, SOL_TCP, TCP_CM_INQ,
					 sizeof(msg->msg_inq), &msg->msg_inq);
		}
	}
	return ret;
}
```

> 1. 일반적인 데이터 수신이 아닌 에러 큐를 읽는 경우 `inet_recv_error()` 실행
> 2. busy_loop가 가능하다면 busy pooling 실행 
 >3. `lock_sock()`함수를 통해 해당 소켓의 락을 획득하고, [[tcp_recvmsg_locked()]]를 호출하게 된다. 그리고 소켓 락을 해제한다. 여기서 나온 결과를 그대로 return 하게 된다.
 >4. 타임스탬프 요청했으면 `tcp_recv_timestamp()` 함수로 전달, 제어메시지(CMSG) 요청했으면 tcp_inq_hint()로 receive_queue에 남은 바이트 수 계산 후 put_cmsg로 전달

[[lock_sock()]]
[[tcp_recvmsg_locked()]]
[[release_sock()]]

