```c title=__tcp_push_pending_frames()
/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets. * The socket must be locked by the caller. */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	if (tcp_write_xmit(sk, cur_mss, nonagle, 0, [[tcp_write_xmit()]]
			   sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk);
}
```
- net/ipv4/tcp_output.c에 구현되어있습니다.
- TCP 연결이 끊어졌다면 바로 종료합니다.
- 전송을 진행한 다음 전송이 실패했다면(`tcp_write_xmit() == true`라면), 시간을 측정합니다.
	- probe timer: 연결이 여전히 살이있음을 확인하기 위한 probe 패킷을 보내는 타이머를 설정합니다. 일정 시간 동안 데이터 송수신이 없으면 probe 패킷을 전송합니다.

### tcp_check_probe_timer()
```c title=tcp_check_probe_timer()
// include/net/tcp.h

struct tcp_sock {
	u32	packets_out;	/* Packets which are "in flight"	*/
}

/** inet_connection_sock - INET connection oriented sock
 *
 * @icsk_pending:	   Scheduled timer event
*  @icsk_timeout: Timeout
 */
struct inet_connection_sock {
	/* inet_sock has to be the first member! */
	struct inet_sock	  icsk_inet;
	...
	__u8			  icsk_pending;
	unsigned long		  icsk_timeout;
	...
};

static inline void tcp_check_probe_timer(struct sock *sk)
{
	if (!tcp_sk(sk)->packets_out && !inet_csk(sk)->icsk_pending)
		tcp_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
				     tcp_probe0_base(sk), TCP_RTO_MAX);
}
```
- 전송 대기 중인 TCP 패킷이 없고(`tcp_sock->packets_out` == 0)
- 예약된 타이머가 없다면(`inet_connection_sock->icsk_pending` == 0)
- probe timer 초기화
### tcp_reset_xmit_timer()
```c title=tcp_reset_xmit_timer()
static inline void tcp_reset_xmit_timer(struct sock *sk,
					const int what,
					unsigned long when,
					const unsigned long max_when)
{
	inet_csk_reset_xmit_timer(sk, what, when + tcp_pacing_delay(sk),
				  max_when);
}
```
- what: 설정할 타이머의 종류(`ICSK_TIME_PROBE0`)
- when: 타이머의 만료 시간
- probe timer를 만료 시간 + 패킷 지연시간?을 총 타이머 시간으로 계산해 초기화
### inet_csk_reset_xmit_timer()
```c title=inet_csk_reset_xmit_timer()
// include/net/inet_connection_sock.h
/*
 *	Reset the retransmission timer
 */
static inline void inet_csk_reset_xmit_timer(struct sock *sk, const int what,
					     unsigned long when,
					     const unsigned long max_when)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (when > max_when) {
		pr_debug("reset_xmit_timer: sk=%p %d when=0x%lx, caller=%p\n",
			 sk, what, when, (void *)_THIS_IP_);
		when = max_when;
	}

	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0 ||
	    what == ICSK_TIME_LOSS_PROBE || what == ICSK_TIME_REO_TIMEOUT) {
		icsk->icsk_pending = what; // 타이머 종류 설정
		icsk->icsk_timeout = jiffie정
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.pending |= ICSK_ACK_TIMER;
		icsk->icsk_ack.timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
	} else {
		pr_debug("inet_csk BUG: unknown timer value\n");
	}
}
```

[[tcp_write_xmit()]]