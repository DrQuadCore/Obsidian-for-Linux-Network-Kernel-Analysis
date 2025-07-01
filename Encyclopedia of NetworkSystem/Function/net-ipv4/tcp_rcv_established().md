---
Parameter:
  - sock
  - sk_buff
Return: void
Location: /net/ipv4/tcp_input.c
---

```c title=tcp_rcv_established코드
/*
* TCP receive function for the ESTABLISHED state.
*
* It is split into a fast path and a slow path. The fast path is
* disabled when:
* - A zero window was announced from us - zero window probing
* is only handled properly in the slow path.
* - Out of order segments arrived.
* - Urgent data is expected.
* - There is no buffer space left
* - Unexpected TCP flags/window values/header lengths are received
* (detected by checking the TCP header against pred_flags)
* - Data is sent in both directions. Fast path only supports pure senders
* or pure receivers (this means either the sequence number or the ack
* value must stay constant)
* - Unexpected TCP option.
*
* When these conditions are not satisfied it drops into a standard
* receive procedure patterned after RFC793 to handle all cases.
* The first three cases are guaranteed by proper pred_flags setting,
* the rest is checked inline. Fast processing is turned on in
* tcp_data_queue when everything is OK.
*/
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
{
	enum skb_drop_reason reason = SKB_DROP_REASON_NOT_SPECIFIED;
	const struct tcphdr *th = (const struct tcphdr *)skb->data;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int len = skb->len;
	  
	/* TCP congestion window tracking */
	trace_tcp_probe(sk, skb);
	  
	tcp_mstamp_refresh(tp);
	if (unlikely(!rcu_access_pointer(sk->sk_rx_dst)))
		inet_csk(sk)->icsk_af_ops->sk_rx_dst_set(sk, skb);
	/*
	* Header prediction.
	* The code loosely follows the one in the famous
	* "30 instruction TCP receive" Van Jacobson mail.
	*
	* Van's trick is to deposit buffers into socket queue
	* on a device interrupt, to call tcp_recv function
	* on the receive process context and checksum and copy
	* the buffer to user space. smart...
	*
	* Our current scheme is not silly either but we take the
	* extra cost of the net_bh soft interrupt processing...
	* We do checksum and copy also but from device to kernel.
	*/
	  
	tp->rx_opt.saw_tstamp = 0;
	  
	/* pred_flags is 0xS?10 << 16 + snd_wnd
	* if header_prediction is to be made
	* 'S' will always be tp->tcp_header_len >> 2
	* '?' will be 0 for the fast path, otherwise pred_flags is 0 to
	* turn it off (when there are holes in the receive
	* space for instance)
	* PSH flag is ignored.
	*/
	  
	if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&
		TCP_SKB_CB(skb)->seq == tp->rcv_nxt &&
		!after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {
		int tcp_header_len = tp->tcp_header_len;
		  
		/* Timestamp header prediction: tcp_header_len
		* is automatically equal to th->doff*4 due to pred_flags
		* match.
		*/
		  
		/* Check timestamp */
		if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
			/* No? Slow path! */
			if (!tcp_parse_aligned_timestamp(tp, th))
			goto slow_path;
			  
			/* If PAWS failed, check it more carefully in slow path */
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
			goto slow_path;
			  
			/* DO NOT update ts_recent here, if checksum fails
			* and timestamp was corrupted part, it will result
			* in a hung connection since we will drop all
			* future packets due to the PAWS test.
			*/
		}
	  
		if (len <= tcp_header_len) {
		/* Bulk data transfer: sender */
			if (len == tcp_header_len) {
				/* Predicted packet is in window by definition.
				* seq == rcv_nxt and rcv_wup <= rcv_nxt.
				* Hence, check seq<=rcv_wup reduces to:
				*/
				if (tcp_header_len ==
					(sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
					tp->rcv_nxt == tp->rcv_wup)
					tcp_store_ts_recent(tp);
		  
				/* We know that such packets are checksummed
				* on entry.
				*/
				tcp_ack(sk, skb, 0);
				__kfree_skb(skb);
				tcp_data_snd_check(sk);
				/* When receiving pure ack in fast path, update
				* last ts ecr directly instead of calling
				* tcp_rcv_rtt_measure_ts()
				*/
				tp->rcv_rtt_last_tsecr = tp->rx_opt.rcv_tsecr;
				return;
			} else { /* Header too small */
				reason = SKB_DROP_REASON_PKT_TOO_SMALL;
				TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
				goto discard;
			}
		} else {
			int eaten = 0;
			bool fragstolen = false;
			  
			if (tcp_checksum_complete(skb))
				goto csum_error;
			  
			if ((int)skb->truesize > sk->sk_forward_alloc
				goto step5;
			  
			/* Predicted packet is in window by definition.
			* seq == rcv_nxt and rcv_wup <= rcv_nxt.
			* Hence, check seq<=rcv_wup reduces to:
			*/
			if (tcp_header_len ==
				(sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				tp->rcv_nxt == tp->rcv_wup)
				tcp_store_ts_recent(tp);
			  
			tcp_rcv_rtt_measure_ts(sk, skb);
			  
			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPHITS);
			  
			/* Bulk data transfer: receiver */
			skb_dst_drop(skb);
			__skb_pull(skb, tcp_header_len);
			eaten = tcp_queue_rcv(sk, skb, &fragstolen);
			  
			tcp_event_data_recv(sk, skb);
			  
			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {
				/* Well, only one small jumplet in fast path... */
				tcp_ack(sk, skb, FLAG_DATA);
				tcp_data_snd_check(sk);
				if (!inet_csk_ack_scheduled(sk))
					goto no_ack;
			} else {
				tcp_update_wl(tp, TCP_SKB_CB(skb)->seq);
			}
  
			__tcp_ack_snd_check(sk, 0);
no_ack:
			if (eaten)
				kfree_skb_partial(skb, fragstolen);
			tcp_data_ready(sk);
			return;
		}
	}
  
slow_path:
	if (len < (th->doff << 2) || tcp_checksum_complete(skb))
		goto csum_error;
	  
	if (!th->ack && !th->rst && !th->syn) {
		reason = SKB_DROP_REASON_TCP_FLAGS;
		goto discard;
	}
	  
	/*
	* Standard slow path.
	*/
	  
	if (!tcp_validate_incoming(sk, skb, th, 1))
		return;
	  
step5:
	reason = tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT);
	if ((int)reason < 0) {
		reason = -reason;
		goto discard;
	}
	tcp_rcv_rtt_measure_ts(sk, skb);
	  
	/* Process urgent data. */
	tcp_urg(sk, skb, th);
	  
	/* step 7: process the segment text */
	tcp_data_queue(sk, skb);
	  
	tcp_data_snd_check(sk);
	tcp_ack_snd_check(sk);
	return;
  
csum_error:
	reason = SKB_DROP_REASON_TCP_CSUM;
	trace_tcp_bad_csum(skb);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
  
discard:
	tcp_drop_reason(sk, skb, reason);
}
```

>맨 처음에 `skb->data`를 캐스팅하여 tcp header를 얻게 된다. 또한, 주어진 소켓을 통해 `tcp_sock`타입의 포인터를 획득한다.
>또한 `len`이라는 변수를 설정하게 되는데, `skb->len`값으로 가져오게 된다.
> flag들과 seqeunce, ack num 이 모두 같은지 확인하고
> 	`tcp_sock`구조체에서 정의된`tcp_header_len`이 주어진 tcp 헤더와 길이가 일치하는지 확인하고, `tcp_parse_aligned_timestamp()`함수를 통해 slow_path인지 확인한다. 이때 주어진 타임스탬프 옵션이 NOP NOP OP_num OP_len 로 포인터로 확인하여 이것이 일치하면 fast_path이다. 또한 PAWS도 확인한다.
> 	
> 	 그 다음으로는 `len`이 `tcp_header_len`보다 작거나 같은 경우를 확인하게 된다. 만약 `len`이 `tcp_header_len`과 같다면 이는 페이로드가 없는 순수한 `ACK` 패킷이라는 것이다.(pure sender)
> 	 이때 만약 둘이 같다면 `tcp_ack()`함수를 통해 incoming pure ACK 패킷들을 다루게 된다.
> 	 그리고 이 후 해당 `skb`를 할당해제하여 bottom half가 끝나게 된다.
> 	 만약 `len`이 `tcp_header_len`보다 작다면, 이는 오류 이므로 discard 하게 된다.
> 	 
> 	 만약 `len` > `tcp_header_len`이라면, 이는 pure receiver라는 뜻이다. 여기서 다시 한 번 checksum 과 truesize, tcp_header_len을 확인하고, RTT를 확인하게 된다.
> 	 이후 `skb`의 `dst_entry`를 드랍하고, tcp 헤더 길이만큼 포인터를 옮긴 다음에 남은 `skb->data`가 페이로드를 가르키게 하여 `tcp_queue_rcv()` 함수를 실행하게 한다. 	이를 `eaten` 변수에 저장하게 된다. 또한 `tcp_event_data_recv()`함수를 실행하여 cwnd가 빠르게 증가할 수 있도록 한다.
> 	 
> 	 그후 ack 확인을 하고 `tcp_ack()`함수를 실행한다. 또한 `tcp_data_snd_check()`함수를 실행하고, 소켓의 윈도우 크기를 업데이트 하며 만약 eaten 된 패킷이 있다면 `tcp_data_ready()`를 실행하여  해당 소켓의 데이터가 준비되었음을 알리게 된다.
> 여기서부터는 slow path이다.
> 	csum과 flag들을 확인하고, `tcp_validate_incoming()`함수를 통해 해당 패킷이 유효한 수신패킷인지 확인하게 된다. 그리고 유효하다면, `tcp_ack()`를 통해 ack 패킷을 보내게 되고, rtt를 측정하고 urgent data를 처리하기 위해 `tcp_urg()`를 실행하게 된다. 마지막으로 `tcp_data_queue`라는 함수를 실행하게 되는데, 이는 slow path에서 데이터를 소켓으로 넣어주는 함수이다. 그후 `tcp_data_snd_check()` 와 `tcp_ack_snd_check()`함수를 실행하고 함수가 종료된다.
> 

---

`trace_tcp_probe()` 

fast path, slow path으로 나누어진다.
tcp flag, sequence number, ack number가 일치한다면 fast path으로 실행한다. 

`if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)`
tsval은 sender가 저장한 timestamp, 보낼 때 찍은 시간이다.
recent는 receiver가 저장한 timestamp, 마지막으로 받은 pkt의 tsval를 저장한다.
만약 받은 패킷의 tsval이 recevier가 저장한 ts_recent 보다 작다는 것은 가장 최근에 받은 패킷보다
먼저 생성이 되었던 패킷이라는 뜻이다. 즉 이는 문제가 있는 패킷이라는 뜻이라 다시 slow path로 
보낸다.
normal case
저번 pkt  : tsval = 10
지금 pkt  : tsval = 11
strange case
저번 pkt  : tsval = 11
지금 pkt  : tsval = 10

`tcp_ack()`를 실행한다. TCP congestion control 과 관련된 기능이 이 함수에서 호출된다.
`tcp_cong_control(), tcp_cwnd_reduction(),....`

`if ((int)skb->truesize > sk->sk_forward_alloc)`
truesize와 sk_forward_alloc을 비교한다. Receive socket buffer에 새로운 패킷 데이터를 추가할 여유 공간이 있는지 확인한다. 공간이 있으면 header prediction은 hit (prediction 성공)이다. \_\_skb_pull를 호출해서 TCP 헤더를 제거하고 tcp_queue_rcv() 호출한고, \_\_skb_queue_tail을 호출해서 패킷을 receive socket buffer에 추가한다. 마지막으로, \_\_tcp_ack_snd_check를 호출해서 ACK 전송이 필요하면 전송한다.

만약 여유 공간이 부족하면 느린 경로를 수행한다. tcp_data_queue 함수는 버퍼 공간을 새로 할당하고 데이터 패킷을 소켓 버퍼에 추가한다. 이때 가능하면 receive socket buffer 크기를 자동으로 증가한다. 빠른 경로와 다르게, tcp_data_snd_check를 호출해서 새로운 데이터 패킷을 전송할 수 있으면 전송하고, 끝으로 tcp_ack_snd_check 호출해서 ACK 전송이 필요하면 ACK 패킷을 생성해서 전송한다.

[[tcp_ack()]]
[[tcp_queue_rcv()]]
[[tcp_data_queue()]]
[[tcp_data_ready()]]
