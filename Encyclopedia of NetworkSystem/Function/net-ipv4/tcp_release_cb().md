---
Parameter:
- sock *
Return:
- void
Location:
- /net/ipv4/tcp_output.c
---
```c title=tcp_release_cb()
/**
 * tcp_release_cb - tcp release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void tcp_release_cb(struct sock *sk)
{
	unsigned long flags = smp_load_acquire(&sk->sk_tsq_flags);
	unsigned long nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		if (!(flags & TCP_DEFERRED_ALL))
			return;
		nflags = flags & ~TCP_DEFERRED_ALL;
	} while (!try_cmpxchg(&sk->sk_tsq_flags, &flags, nflags));

	if (flags & TCPF_TSQ_DEFERRED) {
		tcp_tsq_write(sk);
		__sock_put(sk);
	}

	if (flags & TCPF_WRITE_TIMER_DEFERRED) {
		tcp_write_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_DELACK_TIMER_DEFERRED) {
		tcp_delack_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_MTU_REDUCED_DEFERRED) {
		inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
		__sock_put(sk);
	}
	if ((flags & TCPF_ACK_DEFERRED) && inet_csk_ack_scheduled(sk))
		tcp_send_ack(sk);
}
EXPORT_SYMBOL(tcp_release_cb);
```

TCP 처리 과정에 지연된 작업들을 처리함
> a. TCPF_TSQ_DEFERRED: TCP Small Queue
> b. TCPF_WRITE_TIMER_DEFERRED: 재전송 타이머 처리
> c. TCPF_DELACK_TIMER_DEFERRED: Delayed ACK 전송
> d. TCPF_MTU_REDUCED_DEFERRED: MTU 조정 후 패킷 분할
> e. TCPF_ACK_DEFERRED: ACK 전송
> 
