---
Parameter:
  - list_head
  - sk_buff
Return: sk_buff
Location: /net/ipv4/tcp_offload.c
---

```c title=tcp_gro_receive()
struct sk_buff *tcp_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	struct tcphdr *th;
	struct tcphdr *th2;
	unsigned int len;
	unsigned int thlen;
	__be32 flags;
	unsigned int mss = 1;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	int i;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*th);
	th = skb_gro_header(skb, hlen, off);
	if (unlikely(!th))
		goto out;

	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	hlen = off + thlen;
	if (!skb_gro_may_pull(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	skb_gro_pull(skb, thlen);

	len = skb_gro_len(skb);
	flags = tcp_flag_word(th);

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		th2 = tcp_hdr(p);

		if (*(u32 *)&th->source ^ *(u32 *)&th2->source) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;
	}
	p = NULL;
	goto out_check_final;

found:
	/* Include the IP ID check below from the inner most IP hdr */
	flush = NAPI_GRO_CB(p)->flush;
	flush |= (__force int)(flags & TCP_FLAG_CWR);
	flush |= (__force int)((flags ^ tcp_flag_word(th2)) &
		  ~(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH));
	flush |= (__force int)(th->ack_seq ^ th2->ack_seq);
	for (i = sizeof(*th); i < thlen; i += 4)
		flush |= *(u32 *)((u8 *)th + i) ^
			 *(u32 *)((u8 *)th2 + i);

	/* When we receive our second frame we can made a decision on if we
	 * continue this flow as an atomic flow with a fixed ID or if we use
	 * an incrementing ID.
	 */
	if (NAPI_GRO_CB(p)->flush_id != 1 ||
	    NAPI_GRO_CB(p)->count != 1 ||
	    !NAPI_GRO_CB(p)->is_atomic)
		flush |= NAPI_GRO_CB(p)->flush_id;
	else
		NAPI_GRO_CB(p)->is_atomic = false;

	mss = skb_shinfo(p)->gso_size;

	/* If skb is a GRO packet, make sure its gso_size matches prior packet mss.
	 * If it is a single frame, do not aggregate it if its length
	 * is bigger than our mss.
	 */
	if (unlikely(skb_is_gso(skb)))
		flush |= (mss != skb_shinfo(skb)->gso_size);
	else
		flush |= (len - 1) >= mss;

	flush |= (ntohl(th2->seq) + skb_gro_len(p)) ^ ntohl(th->seq);
#ifdef CONFIG_TLS_DEVICE
	flush |= p->decrypted ^ skb->decrypted;
#endif

	if (flush || skb_gro_receive(p, skb)) { // [[Encyclopedia of NetworkSystem/Function/net-core/skb_gro_receive().md|skb_gro_receive()]]
		mss = 1;
		goto out_check_final;
	}

	tcp_flag_word(th2) |= flags & (TCP_FLAG_FIN | TCP_FLAG_PSH);

out_check_final:
	/* Force a flush if last segment is smaller than mss. */
	if (unlikely(skb_is_gso(skb)))
		flush = len != NAPI_GRO_CB(skb)->count * skb_shinfo(skb)->gso_size;
	else
		flush = len < mss;

	flush |= (__force int)(flags & (TCP_FLAG_URG | TCP_FLAG_PSH |
					TCP_FLAG_RST | TCP_FLAG_SYN |
					TCP_FLAG_FIN));

	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))
		pp = p;

out:
	NAPI_GRO_CB(skb)->flush |= (flush != 0);

	return pp;
}

```

[[Encyclopedia of NetworkSystem/Function/net-core/skb_gro_receive().md|skb_gro_receive()]]

> L4에서 같은 flow인지 확인하는 부분이 들어있다. 함께 들어온 gro_list의 각각의 패킷들에 대하여 같은 포트에서 온건지 확인하여 같은 포트인것이 확인 되면, 바로 found label로 가게 된다. 해당하는 패킷과 찾은 skb를 병합하기 위해 skb_gro_receive()를 실행하게 된다.