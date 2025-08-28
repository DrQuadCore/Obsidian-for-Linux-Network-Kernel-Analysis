```c
/* The "ultimate" congestion control function that aims to replace the rigid
 * cwnd increase and decrease control (tcp_cong_avoid,tcp_*cwnd_reduction).
 * It's called toward the end of processing an ACK with precise rate
 * information. All transmission or retransmission are delayed afterwards.
 */
static void tcp_cong_control(struct sock *sk, u32 ack, u32 acked_sacked,
			     int flag, const struct rate_sample *rs)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->cong_control) {
		icsk->icsk_ca_ops->cong_control(sk, rs);
		return;
	}

	if (tcp_in_cwnd_reduction(sk)) {
		/* Reduce cwnd if state mandates */
		tcp_cwnd_reduction(sk, acked_sacked, rs->losses, flag);
	} else if (tcp_may_raise_cwnd(sk, flag)) {
		/* Advance cwnd if state allows */
		tcp_cong_avoid(sk, ack, acked_sacked);
	}
	tcp_update_pacing_rate(sk);
}
```

- `cong_control` 함수 포인터에 값이 있으면() 해당 함수 실행
- `tcp_in_cwnd_reduction()` 함수로 현재 윈도우가 감소하는 상태인지 확인하고 맞다면 `tcp_cwnd_reduction()` 함수로 cwnd 감소 시키기
- `tcp_may_raise_cwnd()` 함수로 현재 윈도우가 증가 상태인지 확인하고 맞다면 `tcp_cong_avoid()` 함수로 `icsk->icsk_ca_ops->cong_avoid()` 함수 포인터 실행
	- `icsk->icsk_ca_ops`에는 `tcp_init_sock()`함수에서 호출되는 `tcp_assign_congestion_control()` 함수에서 기본값으로 할당하고 추후 변경 가능

```c title=tcp_cwnd_reduction()
void tcp_cwnd_reduction(struct sock *sk, int newly_acked_sacked, int newly_lost, int flag)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int sndcnt = 0;
	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);

	if (newly_acked_sacked <= 0 || WARN_ON_ONCE(!tp->prior_cwnd))
		return;

	tp->prr_delivered += newly_acked_sacked;
	if (delta < 0) {
		u64 dividend = (u64)tp->snd_ssthresh * tp->prr_delivered +
			       tp->prior_cwnd - 1;
		sndcnt = div_u64(dividend, tp->prior_cwnd) - tp->prr_out;
	} else {
		sndcnt = max_t(int, tp->prr_delivered - tp->prr_out,
			       newly_acked_sacked);
		if (flag & FLAG_SND_UNA_ADVANCED && !newly_lost)
			sndcnt++;
		sndcnt = min(delta, sndcnt);
	}
	/* Force a fast retransmit upon entering fast recovery */
	sndcnt = max(sndcnt, (tp->prr_out ? 0 : 1));
	tcp_snd_cwnd_set(tp, tcp_packets_in_flight(tp) + sndcnt);
}
```
