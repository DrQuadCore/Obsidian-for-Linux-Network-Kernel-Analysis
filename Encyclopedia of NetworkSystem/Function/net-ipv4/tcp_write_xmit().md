```c title=tcp_write_xmit()
/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * LARGESEND note: !tcp_urg_mode is overkill, only frames between
 * snd_up-64k-mss .. snd_up cannot be large. However, taking into
 * account rare use of URG, this is not a big flaw.
 *
 * Send at most one packet when push_one > 0. Temporarily ignore
 * cwnd limit to force at most one packet out when push_one == 2.

 * Returns true, if no segments are in flight and we have queued segments,
 * but cannot send anything now because of SWS or another problem.
 */
static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	u32 cwnd_quota, max_segs;
	int result;
	bool is_cwnd_limited = false, is_rwnd_limited = false;

	sent_pkts = 0;

	tcp_mstamp_refresh(tp); // 타임스탬프 갱신
	if (!push_one) { 
		/* Do MTU probing. */
		result = tcp_mtu_probe(sk);
		if (!result) {
			return false;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

	max_segs = tcp_tso_segs(sk, mss_now);
	// TSO 사용시 나눌 수 있는 최대 세그먼트 수 계산 (wnd 한도 고려 X)
	
	while ((skb = tcp_send_head(sk))) { // write 큐의 헤드에서 skb 추출
		unsigned int limit;
		int missing_bytes;

		if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE) {
			/* "skb_mstamp_ns" is used as a start point for the retransmit timer */
			tp->tcp_wstamp_ns = tp->tcp_clock_cache;
			skb_set_delivery_time(skb, tp->tcp_wstamp_ns, SKB_CLOCK_MONOTONIC);
			list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);
			tcp_init_tso_segs(skb, mss_now);
			goto repair; /* Skip network transmission */
		}

		if (tcp_pacing_check(sk))
			break;

		cwnd_quota = tcp_cwnd_test(tp);
		if (!cwnd_quota) {
			if (push_one == 2)
				/* Force out a loss probe pkt. */
				cwnd_quota = 1;
			else
				break;
		} // cwnd에서 더 보낼 수 있는 양 체크
		
		
		cwnd_quota = min(cwnd_quota, max_segs);
		missing_bytes = cwnd_quota * mss_now - skb->len;
		if (missing_bytes > 0)
			tcp_grow_skb(sk, skb, missing_bytes);
		// 보낼 수 있는 양보다 보내야 하는 양이 많다면 남은 데이터를 보내기 위해 skb 확장
		tso_segs = tcp_set_skb_tso_segs(skb, mss_now);
		// tso 활성화시, 몇 개의 segment가 나오는지 계산
		
		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {
			is_rwnd_limited = true;
			break;
		} // 윈도우가 충분한지 체크 ('s'wnd를 테스트하고 'r'wnd를 제한...?)

		if (tso_segs == 1) {
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
				// tso segment가 1개인 경우, nagle 적용여부 확인
		} else {
			if (!push_one &&
			    tcp_tso_should_defer(sk, skb, &is_cwnd_limited,
						 &is_rwnd_limited, max_segs))
				break;
				// cwnd나 rwnd에 의해 전송이 지연되어야하는지 확인
		}

		limit = mss_now;
		if (tso_segs > 1 && !tcp_urg_mode(tp))
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    cwnd_quota,
						    nonagle);
		// tso가 가능하다면 split 단위 계산

		if (skb->len > limit &&
		    unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))
			break;

		if (tcp_small_queue_check(sk, skb, 0))
			break;

		/* Argh, we hit an empty skb(), presumably a thread
		 * is sleeping in sendmsg()/sk_stream_wait_memory().
		 * We do not want to send a pure-ack packet and have
		 * a strange looking rtx queue with empty packet(s).
		 */
		if (TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq)
			break;

		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp))) // [[tcp_transmit_skb()]]
			break;
		// skb 전송
repair:
		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		tcp_event_new_data_sent(sk, skb);

		tcp_minshall_update(tp, mss_now, skb);
		sent_pkts += tcp_skb_pcount(skb);

		if (push_one)
			break;
	}

	if (is_rwnd_limited)
		tcp_chrono_start(sk, TCP_CHRONO_RWND_LIMITED);
	else
		tcp_chrono_stop(sk, TCP_CHRONO_RWND_LIMITED);

	is_cwnd_limited |= (tcp_packets_in_flight(tp) >= tcp_snd_cwnd(tp));
	if (likely(sent_pkts || is_cwnd_limited))
		tcp_cwnd_validate(sk, is_cwnd_limited);

	if (likely(sent_pkts)) {
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += sent_pkts;

		/* Send one loss probe per tail loss episode. */
		if (push_one != 2)
			tcp_schedule_loss_probe(sk, false);
		return false;
	}
	return !tp->packets_out && !tcp_write_queue_empty(sk);
}
```

- TCP Segmentation Offload(TSO): TCP 전송 시 패킷을 분할하는 작업을 CPU가 아닌 NIC이 담당하게 함
1. TSO 사용시 나눌 수 있는 최대 세그먼트 수 계산
2. 소켓의 write queue에서 skb 꺼내서 반복
	1. 허용 전송량(*cwnd_quota*) 계산(`tcp_cwnd_test()`)
	2. 보낼 수 있는 양보다 보내야 하는 양이 많다면 남은 데이터를 보내기 위해 skb 확장(`tcp_grow_skb()`)
	3. TSO 세그먼트 수 계산(`tcp_set_skb_tso_segs()`)
	4. 전송 데이터가 송신 윈도우(swnd)를 넘어간다면 전송 중단(`is_rwnd_limited = true;`)
	5. TSO 세그먼트가 1개라면
		1. Nagle 알고리즘 적용 후 실패 시 종료
	6. TSO 세그먼트가 2개 이상이라면
		1. cwnd나 rwnd에 의해 전송이 지연되어야하는지 확인(`tcp_tso_should_defer()`)
	7. MSS 단위로 분할(`tcp_mss_split_point()` 또는 `tso_fragment()`)
	8. 실제 패킷 전송 [[tcp_transmit_skb()]]
	9. 상태 업데이트
3. write queue가 비었거나, 윈도우 제한, 또는 전송 실패로 반복문 종료
4. 수신 윈도우가 제한되었다면 chrono 타이머 시작, 아니라면 중지
5. 송신 윈도우가 제한되었거나 패킷을 보냈다면 송신 윈도우를 갱신(`tcp_cwnd_validate()`)
6. 최종적으로 패킷이 전송되었다면(senf_pkts > 0) false 반환
7. 전송된 패킷이 없고, write queue는 비어있지 않다면(보내야 하지만 보낼 수 없는 상황이면) true 반환

[[tcp_transmit_skb()]]