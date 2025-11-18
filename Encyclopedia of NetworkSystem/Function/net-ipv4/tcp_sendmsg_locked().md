(주의) 아래 코드는 linux 6.9가 아닌 linux 6.16을 기준으로 작성되었습니다.
제로카피에 관한 최신 코드를 확인하기 위함입니다.
```c title=tcp_sendmsg_locked()
int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct net_devmem_dmabuf_binding *binding = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb;
	struct sockcm_cookie sockc;
	int flags, err, copied = 0;
	int mss_now = 0, size_goal, copied_syn = 0;
	int process_backlog = 0;
	int sockc_err = 0;
	int zc = 0;
	long timeo;

	flags = msg->msg_flags;

	sockc = (struct sockcm_cookie){ .tsflags = READ_ONCE(sk->sk_tsflags) };
	if (msg->msg_controllen) {
		sockc_err = sock_cmsg_send(sk, msg, &sockc);
		/* Don't return error until MSG_FASTOPEN has been processed;
		 * that may succeed even if the cmsg is invalid.
		 */
	}

	if ((flags & MSG_ZEROCOPY) && size) {
		if (msg->msg_ubuf) {
			uarg = msg->msg_ubuf;
			if (sk->sk_route_caps & NETIF_F_SG)
				zc = MSG_ZEROCOPY;
		} else if (sock_flag(sk, SOCK_ZEROCOPY)) {
			skb = tcp_write_queue_tail(sk);
			uarg = msg_zerocopy_realloc(sk, size, skb_zcopy(skb),
						    !sockc_err && sockc.dmabuf_id);
			if (!uarg) {
				err = -ENOBUFS;
				goto out_err;
			}
			if (sk->sk_route_caps & NETIF_F_SG)
				zc = MSG_ZEROCOPY;
			else
				uarg_to_msgzc(uarg)->zerocopy = 0;

			if (!sockc_err && sockc.dmabuf_id) {
				binding = net_devmem_get_binding(sk, sockc.dmabuf_id);
				if (IS_ERR(binding)) {
					err = PTR_ERR(binding);
					binding = NULL;
					goto out_err;
				}
			}
		}
	} else if (unlikely(msg->msg_flags & MSG_SPLICE_PAGES) && size) {
		if (sk->sk_route_caps & NETIF_F_SG)
			zc = MSG_SPLICE_PAGES;
	}

	if (!sockc_err && sockc.dmabuf_id &&
	    (!(flags & MSG_ZEROCOPY) || !sock_flag(sk, SOCK_ZEROCOPY))) {
		err = -EINVAL;
		goto out_err;
	}

	if (unlikely(flags & MSG_FASTOPEN ||
		     inet_test_bit(DEFER_CONNECT, sk)) &&
	    !tp->repair) {
		err = tcp_sendmsg_fastopen(sk, msg, &copied_syn, size, uarg);
		if (err == -EINPROGRESS && copied_syn > 0)
			goto out;
		else if (err)
			goto out_err;
	}

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 전송 타임아웃 계산

	tcp_rate_check_app_limited(sk);  /* is sending application-limited? */
	// applcation-limited 여부 확인

	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(sk)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto do_error;
	}
	// TCP 연결이 되었거나 종료 중이 아니라면, 연결을 대기한다

	if (unlikely(tp->repair)) { // tcp의 repair 모드가 설정되어있는지 확인
		if (tp->repair_queue == TCP_RECV_QUEUE) {
			copied = tcp_send_rcvq(sk, msg, size);
			goto out_nopush;
		}
		// 수신 큐로 전송, 소켓 정보(경로 등)가 제대로 변경되었는지 테스트(시뮬레이션)하고자 수신 큐로 보내보는 것. 일반적인 TCP 전송에서는 발생하지 않는 경로.

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out_err;
		// repair queue가 설정안되어 있으면 오류
		/* 'common' sending to sendq */
	}

	if (sockc_err) {
		err = sockc_err;
		goto out_err;
	}

	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* Ok commence sending. */
	copied = 0;

restart:
	mss_now = tcp_send_mss(sk, &size_goal, flags);
	// mss 계산 및 size_goal 변수 초기화
	
	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;
	// 에러가 발생했거나 종료되었는지 체크

	while (msg_data_left(msg)) { // 남아있는 msg에 대해 반복
		int copy = 0;

		skb = tcp_write_queue_tail(sk);
		if (skb)
			copy = size_goal - skb->len;
		// write queue로부터 skb 가져오고 skb가 null이 아니라면 copy값 감소
		
		trace_tcp_sendmsg_locked(sk, msg, skb, size_goal);

		if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) { // 첫 번째 skb인 경우
			bool first_skb;
	
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_space;

			if (unlikely(process_backlog >= 16)) {
				process_backlog = 0;
				if (sk_flush_backlog(sk))
					goto restart;
			}
			//process_backlog가 꽉찼다면 flush합니다
			
			first_skb = tcp_rtx_and_write_queues_empty(sk);
			// rtx와 write 큐가 비어있는지 확인
			skb = tcp_stream_alloc_skb(sk, sk->sk_allocation,
						   first_skb);
			// skb 할당
			if (!skb)
				goto wait_for_space;

			process_backlog++;

#ifdef CONFIG_SKB_DECRYPTED
			skb->decrypted = !!(flags & MSG_SENDPAGE_DECRYPTED);
#endif
			tcp_skb_entail(sk, skb);
			// write 큐에 enqueue
			copy = size_goal;
			// copy값을 size_goal 값으로 변경
			/* All packets are restored as if they have
			 * already been sent. skb_mstamp_ns isn't set to
			 * avoid wrong rtt estimation.
			 */
			if (tp->repair)
				TCP_SKB_CB(skb)->sacked |= TCPCB_REPAIRED;
		}

		/* Try to append data to the end of skb. */
		if (copy > msg_data_left(msg))
			copy = msg_data_left(msg);
		// copy값이 남은 msg보다 크다면 msg로 변경
		
		if (zc == 0) { // 일반적인 경로
			bool merge = true;
			int i = skb_shinfo(skb)->nr_frags;
			struct page_frag *pfrag = sk_page_frag(sk);

			if (!sk_page_frag_refill(sk, pfrag))
				goto wait_for_space;
			// prfrag에 새 page를 할당
			
			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) { // skb를 coalescing할 수 없는 경우
				if (i >= READ_ONCE(net_hotdata.sysctl_max_skb_frags)) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				} // frag이 최댓값 이상이라면 push라고 마킹
				merge = false;
			}

			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			// 페이지에 남은 양과 복사할 양 중 더 작은 값으로 변경
			
			if (unlikely(skb_zcopy_pure(skb) || skb_zcopy_managed(skb))) {
				if (tcp_downgrade_zcopy_pure(sk, skb))
					goto wait_for_space;
				skb_zcopy_downgrade_managed(skb);
			}

			copy = tcp_wmem_schedule(sk, copy);
			// wmem에 남은 양과 복사할 양 중 더 작은 값으로 변경
			
			if (!copy)
				goto wait_for_space;

			err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
						       pfrag->page,
						       pfrag->offset,
						       copy);
			// 데이터를 skb로 복사합니다
			if (err)
				goto do_error;

			/* Update the skb. */
			if (merge) {
				skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			} else {
				skb_fill_page_desc(skb, i, pfrag->page,
						   pfrag->offset, copy);
				page_ref_inc(pfrag->page);
			}
			pfrag->offset += copy;
		} else if (zc == MSG_ZEROCOPY)  {
			/* First append to a fragless skb builds initial
			 * pure zerocopy skb
			 */
			if (!skb->len)
				skb_shinfo(skb)->flags |= SKBFL_PURE_ZEROCOPY;

			if (!skb_zcopy_pure(skb)) {
				copy = tcp_wmem_schedule(sk, copy);
				if (!copy)
					goto wait_for_space;
			}

			err = skb_zerocopy_iter_stream(sk, skb, msg, copy, uarg,
						       binding);
			if (err == -EMSGSIZE || err == -EEXIST) {
				tcp_mark_push(tp, skb);
				goto new_segment;
			}
			if (err < 0)
				goto do_error;
			copy = err;
		} else if (zc == MSG_SPLICE_PAGES) {
			/* Splice in data if we can; copy if we can't. */
			if (tcp_downgrade_zcopy_pure(sk, skb))
				goto wait_for_space;
			copy = tcp_wmem_schedule(sk, copy);
			if (!copy)
				goto wait_for_space;

			err = skb_splice_from_iter(skb, &msg->msg_iter, copy,
						   sk->sk_allocation);
			if (err < 0) {
				if (err == -EMSGSIZE) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				}
				goto do_error;
			}
			copy = err;

			if (!(flags & MSG_NO_SHARED_FRAGS))
				skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;

			sk_wmem_queued_add(sk, copy);
			sk_mem_charge(sk, copy);
		}

		if (!copied)
			TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

		WRITE_ONCE(tp->write_seq, tp->write_seq + copy);
		TCP_SKB_CB(skb)->end_seq += copy;
		tcp_skb_pcount_set(skb, 0);
		// tcp seq num 설정

		copied += copy;
		if (!msg_data_left(msg)) {
			if (unlikely(flags & MSG_EOR))
				TCP_SKB_CB(skb)->eor = 1;
			goto out;
		} // 보낼 msg가 더이상 없다면 out label로 이동

		if (skb->len < size_goal || (flags & MSG_OOB) || unlikely(tp->repair))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
		// 즉시 전송을 해야한다면 대기 중인 모든 세그먼트들을 넘김
		} else if (skb == tcp_send_head(sk))
			tcp_push_one(sk, mss_now);
			// 현재 skb가 write 큐 맨 앞에 있으면 즉시 전송
		continue;

wait_for_space:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		tcp_remove_empty_skb(sk);
		if (copied)
			tcp_push(sk, flags & ~MSG_MORE, mss_now,
				 TCP_NAGLE_PUSH, size_goal);

		err = sk_stream_wait_memory(sk, &timeo);
		if (err != 0)
			goto do_error;

		mss_now = tcp_send_mss(sk, &size_goal, flags);
	} // while문 종료

out:
	if (copied) {
		tcp_tx_timestamp(sk, &sockc);
		tcp_push(sk, flags, mss_now, tp->nonagle, size_goal); //[[tcp_push()]]
	} // 커널로 복사된 데이터가 있으면 다음 단계로 넘어감
out_nopush:
	/* msg->msg_ubuf is pinned by the caller so we don't take extra refs */
	if (uarg && !msg->msg_ubuf)
		net_zcopy_put(uarg);
	if (binding)
		net_devmem_dmabuf_binding_put(binding);
	return copied + copied_syn;

do_error:
	tcp_remove_empty_skb(sk);

	if (copied + copied_syn)
		goto out;
out_err:
	/* msg->msg_ubuf is pinned by the caller so we don't take extra refs */
	if (uarg && !msg->msg_ubuf)
		net_zcopy_put_abort(uarg, true);
	err = sk_stream_error(sk, flags, err);
	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(tcp_rtx_and_write_queues_empty(sk) && err == -EAGAIN)) {
		sk->sk_write_space(sk);
		tcp_chrono_stop(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
	if (binding)
		net_devmem_dmabuf_binding_put(binding);

	return err;
}
```
- net/ipv4/tcp.c에 구현되어있습니다.
	- linux 6.16과 6.15 버전에 따라 구현이 다릅니다.
		- 6.16은 25년 7월 27일에, 6.15는 25년 5월 25일에 배포되었습니다.
		- 6.16에 제로카피 관련 코드가 추가되었습니다.
- 요약
	1. 소켓 제어 메세지 쿠키(`sockcm_cookie`) 초기화
	2. 데이터 복사 방법에 따라 초기화 작업
	3. 기타 처리
	4. 복사 전 skb 할당
	5. 데이터 복사 방법에 따라 실제 복사
	6. 전체 복사 완료 후 다음 layer로 이동(`tcp_push()`)
- **line 17~23: 소켓 제어 메세지 쿠키 초기화**
```c title=line17~23
	...
	sockc = (struct sockcm_cookie){ .tsflags = READ_ONCE(sk->sk_tsflags) };
	if (msg->msg_controllen) {
		sockc_err = sock_cmsg_send(sk, msg, &sockc);
		/* Don't return error until MSG_FASTOPEN has been processed;
		 * that may succeed even if the cmsg is invalid.
		 */
	}
	...
	  ```
- 부가적인 control msg가 있는지 확인합니다.
- 있다면, 해당 msg를 읽고 타임스탬프 기록, 패킷 우선순위 설정 등 msg따른 부가 처리를 진행합니다.
### sock_cmsg_send()
```c title=sock_cmsg_send()
// net/core/sock.c
struct sockcm_cookie {
	u64 transmit_time;
	u32 mark;
	u32 tsflags;
};
int sock_cmsg_send(struct sock *sk, struct msghdr *msg,
		   struct sockcm_cookie *sockc)
{
	struct cmsghdr *cmsg;
	int ret;

	for_each_cmsghdr(cmsg, msg) { // 모든 cmsg를 순회
		if (!CMSG_OK(msg, cmsg)) // cmsg 유효성 검사
			return -EINVAL;
		if (cmsg->cmsg_level != SOL_SOCKET) // level이 SOL_SOCKET이 아니면 넘어감
			continue;
		ret = __sock_cmsg_send(sk, cmsg, sockc); // 실제 cmsg 처리
		if (ret)
			return ret;
	}
	return 0;
}
EXPORT_SYMBOL(sock_cmsg_send);
```
#### \_\_sock_cmsg_send()
```c __sock_cmsg_send()
int __sock_cmsg_send(struct sock *sk, struct cmsghdr *cmsg,
		     struct sockcm_cookie *sockc)
{
	u32 tsflags;

	switch (cmsg->cmsg_type) {
	// 패킷 마킹 관련 제어
	case SO_MARK:
		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_RAW) && // 권한 검사
		    !ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u32)))
			return -EINVAL;
		sockc->mark = *(u32 *)CMSG_DATA(cmsg); // sock_cookie에 마킹 내용 넣기
		break;
	// 타임스탬핑
	case SO_TIMESTAMPING_OLD:
	case SO_TIMESTAMPING_NEW:
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u32)))
			return -EINVAL;

		tsflags = *(u32 *)CMSG_DATA(cmsg);
		if (tsflags & ~SOF_TIMESTAMPING_TX_RECORD_MASK)
			return -EINVAL;

		sockc->tsflags &= ~SOF_TIMESTAMPING_TX_RECORD_MASK;
		sockc->tsflags |= tsflags; // 플래그 설정
		break;
	case SCM_TXTIME: // 전송 시간 스케줄링
		if (!sock_flag(sk, SOCK_TXTIME))
			return -EINVAL;
		if (cmsg->cmsg_len != CMSG_LEN(sizeof(u64)))
			return -EINVAL;
		sockc->transmit_time = get_unaligned((u64 *)CMSG_DATA(cmsg));
		break;
	/* SCM_RIGHTS and SCM_CREDENTIALS are semantically in SOL_UNIX. */
	case SCM_RIGHTS:
	case SCM_CREDENTIALS:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(__sock_cmsg_send);
```
- cmsg의 유형에 따라 상응하는 cmsg_cookie의 멤버 변수를 채워넣습니다.
	- `mark`: 패킷의 정책 마커
	- `tsflags` : 타임스탬프 관련 플래그. tcp_sendmsg_locked()함수에서 `sk->tsflags`로 이미 초기화된 것에 cmsg의 내용을 비트합 연산으로 추가 
	- `transmit_time`: 패킷의 목표 전송 시간

---
- **25~55: 복사 방식에 따른 초기화 분기**
```c title=line_25~55
	...
	if ((flags & MSG_ZEROCOPY) && size) { // ZEROCOPY가 사용 가능하면
		if (msg->msg_ubuf) { // 1. ubuf가 사용 가능하면
			uarg = msg->msg_ubuf;
			if (sk->sk_route_caps & NETIF_F_SG)
				zc = MSG_ZEROCOPY;
		} else if (sock_flag(sk, SOCK_ZEROCOPY)) { // 2. ubuf가 사용 불가능하고, 소켓에 ZEROCOPY 플래그가 켜져있다면
			skb = tcp_write_queue_tail(sk); // 아직 전송되지 않은 소켓의 마지막 sk_buff 찾기
			uarg = msg_zerocopy_realloc(sk, size, skb_zcopy(skb),
						    !sockc_err && sockc.dmabuf_id); // ubuf 재할당
			if (!uarg) {
				err = -ENOBUFS;
				goto out_err;
			}
			if (sk->sk_route_caps & NETIF_F_SG) // scatter/gather IO가 있다면
				zc = MSG_ZEROCOPY; // 제로카피 활성화
			else
				uarg_to_msgzc(uarg)->zerocopy = 0; // 아니면 ubuf에 제로카피 미지원 알림

			if (!sockc_err && sockc.dmabuf_id) { // DMABUF가 사용 가능하다면
				binding = net_devmem_get_binding(sk, sockc.dmabuf_id);
				if (IS_ERR(binding)) {
					err = PTR_ERR(binding);
					binding = NULL;
					goto out_err;
				}
			}
		}
	} else if (unlikely(msg->msg_flags & MSG_SPLICE_PAGES) && size) {
		if (sk->sk_route_caps & NETIF_F_SG)
			zc = MSG_SPLICE_PAGES;
	}
	...
```
- ZERO Copy 관련 코드입니다.
- ZERO_COPY 플래그가 켜져있다면 다음 세 항목으로 분가합니다.
- (1) msg_ubuf를 사용하고 있다면(즉, userspace의 버퍼에 대한 정보가 있다면)
	- `ubuf_info` 변수인 uarg로 해당 정보를 옮깁니다.
```c title=ubuf_info
/*
 * The callback notifies userspace to release buffers when skb DMA is done in
 * lower device, the skb last reference should be 0 when calling this.
 * The zerocopy_success argument is true if zero copy transmit occurred,
 * false on data copy or out of memory error caused by data copy attempt.
 * The ctx field is used to track device context.
 * The desc field is used to track userspace buffer index.
 */
struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *,
			 bool zerocopy_success); // 패킷 전송 완료 후 사용될 함수
	refcount_t refcnt;
	u8 flags;
};
```

- (2) msg_ubuf를 사용하고 있지 않으나, 소켓에 zero copy 플래그가 켜져있다면
	- 현재 소켓에서 아직 전송되지 않은 마지막 `sk_buff` 구조체를 찾습니다.
	- 이를 통해 uarg 변수에 재할당하고 오류 처리를 진행합니다.
	- `NETIF_F_SG` 플래그로 Scatter/Gather IO가 사용가능한지 확인합니다.
		- 사용 가능하다면 ZEROCOPY가 가능하다고 zc 변수에 저장
		- 불가능하다면 ubuf에 제로카피 플래그를 0으로 바꿉니다.
		- **Scatter/Gather IO란**: 흩어져 있는 여러 버퍼를 한번의 시스템 콜로 처리 가능한 함수들 readv(), writev() 등을 지원하는 것
	- DMABUF가 사용가능하다면 바인딩하고, 실패시 오류 처리로 이동
		- DMABUF란: CPU를 거치지 않고 여러 장치(GPU, NIC 등)가 버퍼를 공유하는 기술
		- https://docs.kernel.org/driver-api/dma-buf.html

- (3) 전송하고자 하는 `msghdr`에 MSG_SPLICE_PAGES 플래그가 켜져있다면
	- 제로카피 대신 MSG_SPLICE_PAGES를 사용하도록 zc 변수에 저장
	- **MSG_SPLICE_PAGES**란: 기존은 페이지별로 처리했지만 여러 페이지를 하나의 splice로 묶어서 처리하는 방법. 작은 크기의 패킷일 경우는 성능이 안좋지만, 대용량의 패킷일 경우 성능 향상
---
- **63~114: 기타 처리**
```c title=line63~114
	...
	if (unlikely(flags & MSG_FASTOPEN ||
		     inet_test_bit(DEFER_CONNECT, sk)) &&
	    !tp->repair) {
		err = tcp_sendmsg_fastopen(sk, msg, &copied_syn, size, uarg);
		if (err == -EINPROGRESS && copied_syn > 0)
			goto out;
		else if (err)
			goto out_err;
	}

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	// 전송 타임아웃 계산

	tcp_rate_check_app_limited(sk);  /* is sending application-limited? */
	// applcation-limited 여부 확인
	
	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&
	    !tcp_passive_fastopen(sk)) {
		err = sk_stream_wait_connect(sk, &timeo);
		if (err != 0)
			goto do_error;
	}
	// TCP 연결이 되었거나 종료 중이 아니라면, 연결을 대기한다

	if (unlikely(tp->repair)) { // tcp의 repair 모드가 설정되어있는지 확인
		if (tp->repair_queue == TCP_RECV_QUEUE) {
			copied = tcp_send_rcvq(sk, msg, size);
			goto out_nopush;
		}
		// 수신 큐로 전송, 소켓 정보(경로 등)가 제대로 변경되었는지 테스트(시뮬레이션)하고자 수신 큐로 보내보는 것. 일반적인 TCP 전송에서는 발생하지 않는 경로.

		err = -EINVAL;
		if (tp->repair_queue == TCP_NO_QUEUE)
			goto out_err;
		// repair queue가 설정안되어 있으면 오류
		/* 'common' sending to sendq */
	}

	if (sockc_err) {
		err = sockc_err;
		goto out_err;
	}

	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* Ok commence sending. */
	copied = 0;
	...
```
- fast open 관련 로직입니다.
- **fast open**이란: TCP 연결 3-way handshake 도중 SYN 신호를 보낼 때 데이터를 같이 보내 전달 시간을 빠르게 하는 기술
	- `tcp_sendmsg_fastopen()`함수로 전송 수행
	- 전송 타임아웃 계산, application-limit 여부 확인
	- TCP 연결이 수립되지 않았다면 연결될 때까지 대기
	- repair 모드가 설정되어있다면 수행(실시간으로 TCP 연결을 수정하는 방식?)
	- 소켓 에러 처리

---
- **116~177: 전송 전 skb 할당
```c title=line116~117
restart:
	mss_now = tcp_send_mss(sk, &size_goal, flags);
	// mss 계산 및 size_goal 변수 초기화
	
	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;
	// 에러가 발생했거나 종료되었는지 체크

	while (msg_data_left(msg)) { // 남아있는 msg에 대해 반복
		int copy = 0;

		skb = tcp_write_queue_tail(sk);
		if (skb)
			copy = size_goal - skb->len;
		// write queue로부터 skb 가져오고 skb가 null이 아니라면 copy값 감소
		
		trace_tcp_sendmsg_locked(sk, msg, skb, size_goal);

		if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) { // 첫 번째 skb인 경우
			bool first_skb;
	
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_space;

			if (unlikely(process_backlog >= 16)) {
				process_backlog = 0;
				if (sk_flush_backlog(sk))
					goto restart;
			}
			//process_backlog가 꽉찼다면 flush합니다
			
			first_skb = tcp_rtx_and_write_queues_empty(sk);
			// rtx와 write 큐가 비어있는지 확인
			skb = tcp_stream_alloc_skb(sk, sk->sk_allocation,
						   first_skb);
			// skb 할당
			if (!skb)
				goto wait_for_space;

			process_backlog++;

#ifdef CONFIG_SKB_DECRYPTED
			skb->decrypted = !!(flags & MSG_SENDPAGE_DECRYPTED);
#endif
			tcp_skb_entail(sk, skb);
			// write 큐에 enqueue
			copy = size_goal;
			// copy값을 size_goal 값으로 변경
			/* All packets are restored as if they have
			 * already been sent. skb_mstamp_ns isn't set to
			 * avoid wrong rtt estimation.
			 */
			if (tp->repair)
				TCP_SKB_CB(skb)->sacked |= TCPCB_REPAIRED;
		}

		/* Try to append data to the end of skb. */
		if (copy > msg_data_left(msg))
			copy = msg_data_left(msg);
		// copy값이 남은 msg보다 크다면 msg로 변경
```
1. MSS(Maximum Segment Size) 계산
2. `msghdr->msg_iter` (남은 메시지 데이터)에 대해 반복
3. `sock->sk_write_queue` 에 있는 `sk_buff` 구조체를 들고 온다. 
4. 목표 바이트 수에서 *skb*의 크기만큼을 빼주어 실제로 복사할 바이트 수를 계산한다.
5. 첫번째 *skb*인 경우
	1. 반복문이 돌아간 횟수를 *process_backlog* 변수에 저장하고, 16이 넘어간다면 소켓의 백로그에 새로운 패킷이 있는지 확인하고 있다면 수신 과정의 처음 라벨(`restart: `)로 돌아간다.
		1. ``` c title=sk_flush_backlog()
		   static inline bool sk_flush_backlog(struct sock *sk)
	{
		if (unlikely(READ_ONCE(sk->sk_backlog.tail))) {
			__sk_flush_backlog(sk); [[__sk_flush_backlog()]]
			return true;
		}
		return false;
	}
	```
	2. `sk_buff` 구조체를 새로 할당 시도한다. 실패했을 경우 `wait_for_space:` 라벨로 이동한다.
	3. 정상적으로 할당했다면*skb*를 `sock->write_queue`에 추가합니다.
	4. 이 경우 skb == 0이므로 복사할 바이트 수는 목표 바이트 수와 동일하다.
6. `msghdr`에 남은 데이터 수가 복사할 바이트 수보다 작다면 남은 데이터 수로 변경한다.
---
- **line 179~229: 실제 전송 수행(제로 카피가 아닐 때)**
```c title=line179~229
if (zc == 0) { // 일반적인 경로
			bool merge = true;
			int i = skb_shinfo(skb)->nr_frags;
			struct page_frag *pfrag = sk_page_frag(sk);

			if (!sk_page_frag_refill(sk, pfrag))
				goto wait_for_space;
			// prfrag에 새 page를 할당
			
			if (!skb_can_coalesce(skb, i, pfrag->page,
					      pfrag->offset)) { // skb를 coalescing할 수 없는 경우
				if (i >= READ_ONCE(net_hotdata.sysctl_max_skb_frags)) {
					tcp_mark_push(tp, skb);
					goto new_segment;
				} // frag이 최댓값 이상이라면 push라고 마킹
				merge = false;
			}

			copy = min_t(int, copy, pfrag->size - pfrag->offset);
			// 페이지에 남은 양과 복사할 양 중 더 작은 값으로 변경
			
			if (unlikely(skb_zcopy_pure(skb) || skb_zcopy_managed(skb))) {
				if (tcp_downgrade_zcopy_pure(sk, skb))
					goto wait_for_space;
				skb_zcopy_downgrade_managed(skb);
			}

			copy = tcp_wmem_schedule(sk, copy);
			// wmem에 남은 양과 복사할 양 중 더 작은 값으로 변경
			
			if (!copy)
				goto wait_for_space;

			err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
						       pfrag->page,
						       pfrag->offset,
						       copy);
			// 데이터를 skb로 복사합니다
			if (err)
				goto do_error;

			/* Update the skb. */
			if (merge) {
				skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
			} else {
				skb_fill_page_desc(skb, i, pfrag->page,
						   pfrag->offset, copy);
				page_ref_inc(pfrag->page);
			}
			pfrag->offset += copy;
		}
```

[[tcp_push()]]