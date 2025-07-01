```C
static int tcp_recvmsg_locked(struct sock *sk, struct msghdr *msg, size_t len,
			      int flags, struct scm_timestamping_internal *tss,
			      int *cmsg_flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0;
	u32 peek_seq;
	u32 *seq;
	unsigned long used;
	int err;
	int target;		/* Read at least this many bytes */
	long timeo;
	struct sk_buff *skb, *last;
	u32 urg_hole = 0;

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	if (tp->recvmsg_inq) {
		*cmsg_flags = TCP_CMSG_INQ;
		msg->msg_get_inq = 1;
	}
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)
		goto recv_urg;

	if (unlikely(tp->repair)) {
		err = -EPERM;
		if (!(flags & MSG_PEEK))
			goto out;

		if (tp->repair_queue == TCP_SEND_QUEUE)
			goto recv_sndq;

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out;

		/* 'common' recv queue MSG_PEEK-ing */
	}

	seq = &tp->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (unlikely(tp->urg_data) && tp->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		/* Next get a buffer. */

		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			last = skb;
			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			if (WARN(before(*seq, TCP_SKB_CB(skb)->seq),
				 "TCP recvmsg seq # bug: copied %X, seq %X, rcvnxt %X, fl %X\n",
				 *seq, TCP_SKB_CB(skb)->seq, tp->rcv_nxt,
				 flags))
				break;

			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (unlikely(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
				pr_err_once("%s: found a SYN, please report !\n", __func__);
				offset--;
			}
			if (offset < skb->len)
				goto found_ok_skb;
			if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
				goto found_fin_ok;
			WARN(!(flags & MSG_PEEK),
			     "TCP recvmsg seq # bug 2: copied %X, seq %X, rcvnxt %X, fl %X\n",
			     *seq, TCP_SKB_CB(skb)->seq, tp->rcv_nxt, flags);
		}

		/* Well, if we have backlog, try to process it now yet. */

		if (copied >= target && !READ_ONCE(sk->sk_backlog.tail))
			break;

		if (copied) {
			if (!timeo ||
			    sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				copied = -ENOTCONN;
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			__sk_flush_backlog(sk);
		} else {
			tcp_cleanup_rbuf(sk, copied);
			err = sk_wait_data(sk, &timeo, last);
			if (err < 0) {
				err = copied ? : err;
				goto out;
			}
		}

		if ((flags & MSG_PEEK) &&
		    (peek_seq - copied - urg_hole != tp->copied_seq)) {
			net_dbg_ratelimited("TCP(%s:%d): Application bug, race in MSG_PEEK\n",
					    current->comm,
					    task_pid_nr(current));
			peek_seq = tp->copied_seq;
		}
		continue;

found_ok_skb:
		/* Ok so how much can we use? */
		used = skb->len - offset;
		if (len < used)
			used = len;

		/* Do we have urgent data here? */
		if (unlikely(tp->urg_data)) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						WRITE_ONCE(*seq, *seq + 1);
						urg_hole++;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}

		if (!(flags & MSG_TRUNC)) {
			err = skb_copy_datagram_msg(skb, offset, msg, used);
			if (err) {
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		WRITE_ONCE(*seq, *seq + used);
		copied += used;
		len -= used;

		tcp_rcv_space_adjust(sk);

skip_copy:
		if (unlikely(tp->urg_data) && after(tp->copied_seq, tp->urg_seq)) {
			WRITE_ONCE(tp->urg_data, 0);
			tcp_fast_path_check(sk);
		}

		if (TCP_SKB_CB(skb)->has_rxtstamp) {
			tcp_update_recv_tstamps(skb, tss);
			*cmsg_flags |= TCP_CMSG_TS;
		}

		if (used + offset < skb->len)
			continue;

		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN)
			goto found_fin_ok;
		if (!(flags & MSG_PEEK))
			tcp_eat_recv_skb(sk, skb);
		continue;

found_fin_ok:
		/* Process the FIN. */
		WRITE_ONCE(*seq, *seq + 1);
		if (!(flags & MSG_PEEK))
			tcp_eat_recv_skb(sk, skb);
		break;
	} while (len > 0);

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	tcp_cleanup_rbuf(sk, copied);
	return copied;

out:
	return err;

recv_urg:
	err = tcp_recv_urg(sk, msg, len, flags);
	goto out;

recv_sndq:
	err = tcp_peek_sndq(sk, msg, len);
	goto out;
}
```

> timestamp와 urgent data 등을 처리하고 난 뒤, `sock_rcvlowat()`함수를 통해 수신 받을 길이를 설정하게 된다. 최소한 이 길이 만큼은 읽어야  한 번의 수신 루틴이 끝나게 된다.
> 
> 그 다음은 do - while 문으로 len보다 많은 길이를 받을 때까지 계속 복사를 하게 되는데, 우선은 `skb_peek_tail`을 통해 수신 큐의 가장 마지막 패킷을 찾은 다음에, `skb_queue_walk()`함수를 통해 해당 수신 큐를 처음부터 반복하게 된다. 그 다음 각종 오류들을 탐색하며 만약 오류가 발생했을 시에 이를 경고하고, `last`에는 해당 `skb`가 저장될 것이다. 아니라면 중간에 오프셋을 확인하여 정상적인 skb를 가지고 `goto found_ok_skb`를 통해 해당 skb를 처리하는 루틴으로 넘어가게 된다.
> 
> 그 후 만약 수신 큐에서 모두 복사가 완료되어 `copied >= target`이라면 백로그를 처리하지 않고 `break`가 된다. 그 외에도 `sk->sk_shutdown`을 `RCV_SHUTDOWN`과 비트 & 연산을 하여 종료 조건을 확인한다.
> 
> 이후 다시 `copied >= target`이라면 `__sk_flush_backlog()`함수를 호출하여 백로그를 처리하게 된다. 만약 위의 조건을 만족하지 않는다면 `tcp_cleanup_rbuf()`함수를 호출하여 수신 큐를 정리하고, `sk_wait_data()`함수를 시행하게 된다.
> 
> 
> `found_ok_skb:`
> 사용할 수 있는 길이를 게산하고, urg_data인 경우 먼저 처리를 해주며, 메인 루틴은 `skb_copy_datagram_msg()`를 통해 이루어진다. 이렇게 user space로 copy가 이루어지고 난 뒤에는 tcp 소켓의 수신 큐가 적절한 길이를 가질 수 있게 `tcp_rcv_space_adjust()`함수가 호출되게 된다.
> 그렇게 처음 인자로 받은 `len`에서 복사한 길이 만큼 계속 빼게 되고, do -while 문은 이 길이가 0보다 작아졌을 때 종료되게 된다.
> 
> 마지막으로 한번 더 `tcp_cleanup_rbuf()`를 호출하고 난 뒤 함수가 `copied`를 반환하며 종료된다.

[[__sk_flush_backlog()]]
[[sk_wait_data()]]
[[skb_copy_datagram_msg()]]
