```c title=__tcp_transmit_skb()
/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
			      int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct sk_buff *oskb = NULL;
	struct tcp_key key;
	struct tcphdr *th;
	u64 prior_wstamp;
	int err;

	BUG_ON(!skb || !tcp_skb_pcount(skb));
	// skb 유효성 검사
	tp = tcp_sk(sk);
	prior_wstamp = tp->tcp_wstamp_ns;
	tp->tcp_wstamp_ns = max(tp->tcp_wstamp_ns, tp->tcp_clock_cache);
	skb_set_delivery_time(skb, tp->tcp_wstamp_ns, SKB_CLOCK_MONOTONIC);
	// 타임스탬프 관련
	
	if (clone_it) { // clone_it이 1인 경우 skb 복제 (추후 재전송을 위해 복제)
		oskb = skb;

		tcp_skb_tsorted_save(oskb) {
			if (unlikely(skb_cloned(oskb)))
				skb = pskb_copy(oskb, gfp_mask);
			// 이미 복사된 skb라면 (다른 곳에서 참조중이라면) deep copy
			else
				skb = skb_clone(oskb, gfp_mask);
				// 그렇지 않으면 shallow copy
		} tcp_skb_tsorted_restore(oskb);

		if (unlikely(!skb))
			return -ENOBUFS;
		/* retransmit skbs might have a non zero value in skb->dev
		 * because skb->dev is aliased with skb->rbnode.rb_left
		 */
		skb->dev = NULL;
	}

	inet = inet_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	tcp_get_current_key(sk, &key);
	if (unlikely(tcb->tcp_flags & TCPHDR_SYN)) {
		// SYN 패킷인 경우
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &key); // SYN 패킷 용 옵션 추가
	} else {
		tcp_options_size = tcp_established_options(sk, skb, &opts, &key); // 그외 패킷용 옵션 추가
		/* Force a PSH flag on all (GSO) packets to expedite GRO flush
		 * at receiver : This slightly improve GRO performance.
		 * Note that we do not force the PSH flag for non GSO packets,
		 * because they might be sent under high congestion events,
		 * and in this case it is better to delay the delivery of 1-MSS
		 * packets and thus the corresponding ACK packet that would
		 * release the following packet.
		 */
		if (tcp_skb_pcount(skb) > 1)
			tcb->tcp_flags |= TCPHDR_PSH;
	} // TSO/GSO 패킷이면 PUSH 플래그 설정
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr); // tcp 헤더 사이즈

	/* We set skb->ooo_okay to one if this packet can select
	 * a different TX queue than prior packets of this flow,
	 * to avoid self inflicted reorders.
	 * The 'other' queue decision is based on current cpu number
	 * if XPS is enabled, or sk->sk_txhash otherwise.
	 * We can switch to another (and better) queue if:
	 * 1) No packet with payload is in qdisc/device queues.
	 *    Delays in TX completion can defeat the test
	 *    even if packets were already sent.
	 * 2) Or rtx queue is empty.
	 *    This mitigates above case if ACK packets for
	 *    all prior packets were already processed.
	 */
	skb->ooo_okay = sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) ||
			tcp_rtx_queue_empty(sk);
	// write buffer와 retransmission queue가 비어있는 경우에만 xps 허용
	// order가 꼬이는 것을 방지지

	/* If we had to use memory reserve to allocate this skb,
	 * this might cause drops if packet is looped back :
	 * Other socket might not have SOCK_MEMALLOC.
	 * Packets not looped back do not care about pfmemalloc.
	 */
	skb->pfmemalloc = 0;

	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);
	// skb에 헤더 포인터 수정
	skb_orphan(skb);
	// sk로부터 분리(참조 카운터 감소)
	skb->sk = sk;
	// accounting을 위해서 포인터만 남겨둠
	skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree; // skb desctructor 함수 할당
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);
	// 메모리 사용량 수정

	skb_set_dst_pending_confirm(skb, READ_ONCE(sk->sk_dst_pending_confirm));

	/* Build TCP header and checksum it. */
	th = (struct tcphdr *)skb->data;
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					(tcb->tcp_flags & TCPHDR_FLAGS_MASK));

	th->check		= 0;
	th->urg_ptr		= 0;
	// tcp 헤더 수정
	
	/* The urg_mode check is necessary during a below snd_una win probe */
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = htons(0xFFFF);
			th->urg = 1;
		}
	} //urg 모드 처리, 포인터 설정

	skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
		th->window      = htons(tcp_select_window(sk));
		tcp_ecn_send(sk, skb, th, tcp_header_size);
		// SYN 패킷이 아닌 애들은 swnd보고 window 헤더 설정
	} else {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	}

	tcp_options_write(th, tp, NULL, &opts, &key);

	if (tcp_key_is_md5(&key)) {
#ifdef CONFIG_TCP_MD5SIG
		/* Calculate the MD5 hash, as we have all we need now */
		sk_gso_disable(sk);
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       key.md5_key, sk, skb);
#endif
	} else if (tcp_key_is_ao(&key)) {
		int err;

		err = tcp_ao_transmit_skb(sk, skb, key.ao_key, th,
					  opts.hash_location);
		if (err) {
			kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
			return -ENOMEM;
		}
	} // 그 외 옵션..

	/* BPF prog is the last one writing header option */
	bpf_skops_write_hdr_opt(sk, skb, NULL, NULL, 0, &opts);

	INDIRECT_CALL_INET(icsk->icsk_af_ops->send_check,
			   tcp_v6_send_check, tcp_v4_send_check,
			   sk, skb);
	// 체크섬 계산

	if (likely(tcb->tcp_flags & TCPHDR_ACK))
		tcp_event_ack_sent(sk, rcv_nxt);

	if (skb->len != tcp_header_size) {
		tcp_event_data_sent(tp, sk);
		tp->data_segs_out += tcp_skb_pcount(skb);
		tp->bytes_sent += skb->len - tcp_header_size;
	}

	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      tcp_skb_pcount(skb));

	tp->segs_out += tcp_skb_pcount(skb);
	skb_set_hash_from_sk(skb, sk);
	/* OK, its time to fill skb_shinfo(skb)->gso_{segs|size} */
	skb_shinfo(skb)->gso_segs = tcp_skb_pcount(skb);
	skb_shinfo(skb)->gso_size = tcp_skb_mss(skb);

	/* Leave earliest departure time in skb->tstamp (skb->skb_mstamp_ns) */

	/* Cleanup our debris for IP stacks */
	memset(skb->cb, 0, max(sizeof(struct inet_skb_parm),
			       sizeof(struct inet6_skb_parm)));

	tcp_add_tx_delay(skb, tp);

	err = INDIRECT_CALL_INET(icsk->icsk_af_ops->queue_xmit,
				 inet6_csk_xmit, ip_queue_xmit,
				 sk, skb, &inet->cork.fl);
	// l3로 이동

	if (unlikely(err > 0)) {
		tcp_enter_cwr(sk);
		err = net_xmit_eval(err);
	}
	if (!err && oskb) {
		tcp_update_skb_after_send(sk, oskb, prior_wstamp);
		tcp_rate_skb_sent(sk, oskb);
	}
	return err;
}
```
- 현재 skb들은 헤더가 없는 상태이므로 TCP 헤더를 생성해야 한다.

1. 유효성 검사와 타임스탬프 갱신
2. 추후 재전송을 위해 소켓을 복사해야 한다면
	1. 이미 이전에 복사되었다면 깊은 복사 수행
	2. 아니면 얕은 복사 수행
3. `inet_sock`, `tcp_skb_cb` 등 구조체 초기화, 키 획득
4. SYN 패킷인 경우 SYN 패킷용 옵션(`tcp_syn_option()`), 그 외 패킷일 경우 기본 옵션(`tcp_established_options()`) 추가
5. write buffer(QDisk/device queue)와 retransmission queue가 비어있는 경우에만 Transmit Packet Steering(XPS) 허용
6. SKB 관련 처리
	1. SKB의 헤더 포인터 위치 수정(`skb_reset_transport_header()`)
	2. 소켓과 SKB 분리(`skb_orphan()`). 이때 destructor 콜백 함수를 사용하고 NULL로 초기화함
	3. `sk_buff->destructor`에 다시 함수 할당
	4. SKB가 데이터를 포함하지 않는 순수한 ACK 신호라면(`skb_is_tcp_pure_ack()`에 전용 자원 해제 함수(`__sock_wfree()`), 아니라면 기본 TCP용 자원 해제 함수(`tcp_wfree()`)를 다시 할당
7. TCP 헤더 초기화 및 값 할당
	1. flag가 저장될 위치는 TCP 헤더(*th*)를 16비트 단위로 6번째 (=헤드에서 12바이트 뒤)에 저장
8. URG 모드 처리
9. TCP 윈도우 계산
	1. SYN 패킷이 아니라면 TCP 패킷의 윈도우를 설정하고, ecn 플래그도 설정
	2. SYN 또는 SYN+ACK 패킷이면 수신 윈도우 크기로 설정
10. `tcp_v4_send_check()`로 체크섬 계산
11. `ip_queue_xmit()`으로 다음 레이어로 이동

[[ip_queue_xmit()]]

---
### tcp_select_window()
```c title=tcp_select_window()
/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	u32 old_win = tp->rcv_wnd;
	u32 cur_win, new_win;

	/* Make the window 0 if we failed to queue the data because we
	 * are out of memory. The window is temporary, so we don't store
	 * it on the socket.
	 */
	if (unlikely(inet_csk(sk)->icsk_ack.pending & ICSK_ACK_NOMEM))
		return 0;

	cur_win = tcp_receive_window(tp);
	new_win = __tcp_select_window(sk);
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		if (!READ_ONCE(net->ipv4.sysctl_tcp_shrink_window) || !tp->rx_opt.rcv_wscale) {
			/* Never shrink the offered window */
			if (new_win == 0)
				NET_INC_STATS(net, LINUX_MIB_TCPWANTZEROWINDOWADV);
			new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
		}
	}

	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale &&
	    READ_ONCE(net->ipv4.sysctl_tcp_workaround_signed_windows))
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0) {
		tp->pred_flags = 0;
		if (old_win)
			NET_INC_STATS(net, LINUX_MIB_TCPTOZEROWINDOWADV);
	} else if (old_win == 0) {
		NET_INC_STATS(net, LINUX_MIB_TCPFROMZEROWINDOWADV);
	}

	return new_win;
}
```
### tcp_ecn_send()
```c title=tcp_ecn_send()
/* Set up ECN state for a packet on a ESTABLISHED socket that is about to
 * be sent.
 */
static void tcp_ecn_send(struct sock *sk, struct sk_buff *skb,
			 struct tcphdr *th, int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {
			INET_ECN_xmit(sk);
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				th->cwr = 1;
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}
		} else if (!tcp_ca_needs_ecn(sk)) {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			th->ece = 1;
	}
}
```