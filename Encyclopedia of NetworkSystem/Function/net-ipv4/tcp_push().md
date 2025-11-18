```c title=tcp_push()
void tcp_push(struct sock *sk, int flags, int mss_now,
	      int nonagle, int size_goal)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	skb = tcp_write_queue_tail(sk);
	if (!skb)
		return;
	if (!(flags & MSG_MORE) || forced_push(tp))
		tcp_mark_push(tp, skb);

	tcp_mark_urg(tp, flags);

	if (tcp_should_autocork(sk, skb, size_goal)) {

		/* avoid atomic op if TSQ_THROTTLED bit is already set */
		if (!test_bit(TSQ_THROTTLED, &sk->sk_tsq_flags)) {
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPAUTOCORKING);
			set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);
			smp_mb__after_atomic();
		}
		/* It is possible TX completion already happened
		 * before we set TSQ_THROTTLED.
		 */
		if (refcount_read(&sk->sk_wmem_alloc) > skb->truesize)
			return;
	}

	if (flags & MSG_MORE)
		nonagle = TCP_NAGLE_CORK;

	__tcp_push_pending_frames(sk, mss_now, nonagle); //[[__tcp_push_pending_frames]]
}
```
- net/ipv4/tcp.c에 구현되어있습니다.
- write 큐에서 skb를 가져오고 MSG_MORE 플래그가 없거나 강제 push가 가능한 경우, 마킹을 진행합니다.
- `MSB_OOB`(out-of-band) 플래그가 있다면, URG 플래그를 설정합니다.
```c title=tcp_mark_urg()
static inline void tcp_mark_urg(struct tcp_sock *tp, int flags)
{
	if (flags & MSG_OOB)
		tp->snd_up = tp->write_seq;
}
```
- 자동 corking이 가능하다면 Transmit 큐에 대해서 플래그를 설정하여 지연시킵니다.
- MSG_MORE 플래그가 활성되어있는 경우, nonagle 값을 변경합니다.
---
- **nagle 알고리즘이란**
	- 데이터가 쌓일 때까지 기다리다가 일정 크기가 되면 패킷을 전송하는 방식
	- MSS보다 작은 데이터는 큐에 쌓아두었다가 이전 데이터의 ACK가 오거나, 일정 크기가 되면 전송
- **TCP_CORK란**
	- 유저 영역에서 지정할 수 있는 플래그로, 켜져있다면 데이터 전송이 막혀 데이터를 모아 서 보낼 수 있음.
- **autocorking이란**
```c title=tcp_should_autocork()
/* If a not yet filled skb is pushed, do not send it if
 * we have data packets in Qdisc or NIC queues :
 * Because TX completion will happen shortly, it gives a chance
 * to coalesce future sendmsg() payload into this skb, without
 * need for a timer, and with no latency trade off.
 * As packets containing data payload have a bigger truesize
 * than pure acks (dataless) packets, the last checks prevent
 * autocorking if we only have an ACK in Qdisc/NIC queues,
 * or if TX completion was delayed after we processed ACK packet.
 */
static bool tcp_should_autocork(struct sock *sk, struct sk_buff *skb,
				int size_goal)
{
	return skb->len < size_goal && 
	       READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_autocorking) &&
	       !tcp_rtx_queue_empty(sk) &&
	       refcount_read(&sk->sk_wmem_alloc) > skb->truesize &&
	       tcp_skb_can_collapse_to(skb);
}
```
- 다음 조건을 만족한다면
	- 현재 패킷 크키가 목표 전송 크기보다 작고
	- 소켓의 `net` 구조체에 autocorking이 1로 설정되어 있고
	- 소켓의 전송 큐에 패킷이 존재하고
	- 소켓의 송신 버퍼(NIC 큐 또는 Qdisk)에 ACK가 아닌 실제 데이터가 존재하고
	- skb에 더 합칠 수 있다면
- `TSQ_THROTTLED`(TCP Small Queue의 상태가 현재 소켓 전송 중지 상태임) 플래그를 설정
- race condtion이 생길 수 있어 다시 소켓의 송신 버퍼에 데이터가 있는지 확인하고 있다면 중지, 없다면 전송 계속

[[__tcp_push_pending_frames()]]