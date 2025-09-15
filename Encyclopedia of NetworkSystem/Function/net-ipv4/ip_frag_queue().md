### 3.3.3. ip_frag_queue()
```c
/* Add new segment to existing queue. */
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct net *net = qp->q.fqdir->net;// 네트워크 네임스페이스
	int ihl, end, flags, offset;// 헤더 길이, 데이터 끝 위치, 플래그그
	struct sk_buff *prev_tail;//이전 마지막 fragment
	struct net_device *dev;//skb가 들어온 네트워크 디바이스
	unsigned int fragsize;// 새로 들어온 fragment 크기
	int err = -ENOENT;
	SKB_DR(reason);
	u8 ecn;

	/* If reassembly is already done, @skb must be a duplicate frag. */
	// 새로 들어온 fragment가 이미 합쳐졌다면 넘어감
	if (qp->q.flags & INET_FRAG_COMPLETE) {
		SKB_DR_SET(reason, DUP_FRAG);
		goto err;
	}

	// a. ipq 상태를 확인하고 초기화 시도, 안되면 제거 후 넘어감
	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}

	// b. offset, flag 계산
	ecn = ip4_frag_ecn(ip_hdr(skb)->tos);
	offset = ntohs(ip_hdr(skb)->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);

	// c. end 계산
	/* Determine the position of this fragment. */
	end = offset + skb->len - skb_network_offset(skb) - ihl;
	err = -EINVAL;

	// d. fragment 검증
	/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrupted.
		 */
		if (end < qp->q.len ||
		    ((qp->q.flags & INET_FRAG_LAST_IN) && end != qp->q.len))
			goto discard_qp;
		qp->q.flags |= INET_FRAG_LAST_IN;
		qp->q.len = end;
	} else {
		if (end&7) {
			end &= ~7;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
		if (end > qp->q.len) {
			/* Some bits beyond end -> corruption. */
			if (qp->q.flags & INET_FRAG_LAST_IN)
				goto discard_qp;
			qp->q.len = end;
		}
	}
	if (end == offset)
		goto discard_qp;

	err = -ENOMEM;
	if (!pskb_pull(skb, skb_network_offset(skb) + ihl))
		goto discard_qp;

	err = pskb_trim_rcsum(skb, end - offset);
	if (err)
		goto discard_qp;

	// e. fragment 삽입
	/* Note : skb->rbnode and skb->dev share the same location. */
	dev = skb->dev;
	/* Makes sure compiler wont do silly aliasing games */
	barrier();

	prev_tail = qp->q.fragments_tail;
	err = inet_frag_queue_insert(&qp->q, skb, offset, end);
	if (err)
		goto insert_error;

	if (dev)
		qp->iif = dev->ifindex;

	qp->q.stamp = skb->tstamp;
	qp->q.mono_delivery_time = skb->mono_delivery_time;
	qp->q.meat += skb->len;
	qp->ecn |= ecn;
	add_frag_mem_limit(qp->q.fqdir, skb->truesize);
	if (offset == 0)
		qp->q.flags |= INET_FRAG_FIRST_IN;

	// f. fragment 크기 계산, 최대 fragment 크기 계산
	fragsize = skb->len + ihl;

	if (fragsize > qp->q.max_size)
		qp->q.max_size = fragsize;

	if (ip_hdr(skb)->frag_off & htons(IP_DF) &&
	    fragsize > qp->max_df_size)
		qp->max_df_size = fragsize;

	if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    qp->q.meat == qp->q.len) {
		unsigned long orefdst = skb->_skb_refdst;

		skb->_skb_refdst = 0UL;
		err = ip_frag_reasm(qp, skb, prev_tail, dev);
		skb->_skb_refdst = orefdst;
		if (err)
			inet_frag_kill(&qp->q);
		return err;
	}

	// g. 재조립되지 않은 경우
	skb_dst_drop(skb);
	skb_orphan(skb);
	return -EINPROGRESS;

insert_error:
	if (err == IPFRAG_DUP) {
		SKB_DR_SET(reason, DUP_FRAG);
		err = -EINVAL;
		goto err;
	}
	err = -EINVAL;
	__IP_INC_STATS(net, IPSTATS_MIB_REASM_OVERLAPS);
discard_qp:
	inet_frag_kill(&qp->q);
	__IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
err:
	kfree_skb_reason(skb, reason);
	return err;
}
```

**a. ipq 상태를 확인하고 초기화 시도, 안되면 제거 후 넘어감**
```c
// ipq 상태를 확인하고 초기화 시도, 안되면 제거 후 넘어감
	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}
```

```c
/* Is the fragment too far ahead to be part of ipq? */
static int ip_frag_too_far(struct ipq *qp)
{
	struct inet_peer *peer = qp->peer;  // IP 패킷의 목적지 정보를 나타내는 구조체
	unsigned int max = qp->q.fqdir->max_dist;  // 가능한 최대 거리
	unsigned int start, end;

	int rc;

	if (!peer || !max)
		return 0;

	start = qp->rid;
	end = atomic_inc_return(&peer->rid);
	qp->rid = end;

	rc = qp->q.fragments_tail && (end - start) > max;

	if (rc)
		__IP_INC_STATS(qp->q.fqdir->net, IPSTATS_MIB_REASMFAILS);

	return rc;
}

static int ip_frag_reinit(struct ipq *qp)
{
	unsigned int sum_truesize = 0;

	if (!mod_timer(&qp->q.timer, jiffies + qp->q.fqdir->timeout)) {
		refcount_inc(&qp->q.refcnt);
		return -ETIMEDOUT;
	}

	sum_truesize = inet_frag_rbtree_purge(&qp->q.rb_fragments,
					      SKB_DROP_REASON_FRAG_TOO_FAR);
	sub_frag_mem_limit(qp->q.fqdir, sum_truesize);

	qp->q.flags = 0;
	qp->q.len = 0;
	qp->q.meat = 0;
	qp->q.rb_fragments = RB_ROOT;
	qp->q.fragments_tail = NULL;
	qp->q.last_run_head = NULL;
	qp->iif = 0;
	qp->ecn = 0;

	return 0;
}


```
---
**b. offset 계산**
```c
	ecn = ip4_frag_ecn(ip_hdr(skb)->tos);
	offset = ntohs(ip_hdr(skb)->frag_off);
	// flags와 offset 분리
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);
```

```c
// include/net/ip.h
static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}
```
iphdr->ihl은 word 단위이므로 바이트 단위로 연산하기 위해 4를 곱함

---
**c. end 계산**
```c
	/* Determine the position of this fragment. */
	end = offset + skb->len - skb_network_offset(skb) - ihl;
	err = -EINVAL;
```

```c
static inline int skb_network_offset(const struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}
static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}
```
- offset: 해당 fragment의 데이터 부분이 원본 IP 패킷 내에서 시작하는 바이트 위치
- skb->len: 해당 sk_buff의 전체 길이
- skb_network_offset(skb): 현재 sk_buff에서 IP 헤더가 시작하는 위치
- ihl: IP 헤더의 길이
	--> end = offset + (fragment의 길이) = IP 데이터그램 내에서 fragment 데이터의 끝나는 바이트 위치

---

**d. 마지막 fragment인지 확인**
```c
/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrupted.
		 */
		if (end < qp->q.len ||
		    ((qp->q.flags & INET_FRAG_LAST_IN) && end != qp->q.len))
			goto discard_qp;
		qp->q.flags |= INET_FRAG_LAST_IN;
		qp->q.len = end;
	} 
```
- 첫번째 if문: fragment가 마지막인지(`0`) 아닌지(`1`) 확인
	- 마지막이면 전체 데이터그램의 크기를 계산 가능함
	- 만약 이상한 fragment면(기존 길이보다 작거나 이미 마지막이 들어왔는데 최종 길이랑 다르면) 해당 패킷은 버림
	- ipq 구조체에 마지막 패킷이 들어왔다는 플래그(`INET_FRAG_LAST_IN` )설정
	- `(struct ipq *)qp->(struct inet_frag_queue)q.(int)len`에 `end`를 저장
```c
	else {
		if (end&7) {
			end &= ~7;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
		if (end > qp->q.len) {
			/* Some bits beyond end -> corruption. */
			if (qp->q.flags & INET_FRAG_LAST_IN)
				goto discard_qp;
			qp->q.len = end;
		}
	}
	if (end == offset)
		goto discard_qp;
```
- 아직 마지막 fragment가 아니면
	- fragment는 8바이트 단위이기 때문에 항상 8의 배수임. 따라서 뒤 3비트에 값이 있으면 그걸 버림(`end &= ~7;`)
	```c
	/*
	 * @ip_summed: Driver fed us an IP checksum
	 */
struct sk_buff {
	__u8			ip_summed:2;
}
	```
	 - NIC에서 이미 체크섬을 계산했다면 값을 수정했으니 다시 계산해야하는 상태(`CHECKSUM_NONE`)로 바꿈
	 - 새로 들어온 fragment의 끝 위치가 지금까지의 전체 길이보다 크다면
		 - 이미 마지막 fragment를 받았다면 해당 패킷은 버림
		 - 아니면 전체 길이를 `end`로 저장
- 시작 위치와 끝 위치가 같다면 해당 패킷은 버림

---

**e. fragment 삽입**
```c
	/* Note : skb->rbnode and skb->dev share the same location. */
	dev = skb->dev;
	/* 컴파일러 메모리 최적화를 방지해 dev값 유지 */
	barrier();

	// iqp 구조체 내에서 가장 뒤 fragment의 sk_buff 들고 오기
	/**
	 * struct inet_frag_queue - fragment queue 
	 * @fragments_tail: received fragments tail
	 */
	prev_tail = qp->q.fragments_tail;
	// iqp에 새로운 fragment 삽입하기
	err = inet_frag_queue_insert(&qp->q, skb, offset, end);
	if (err)
		goto insert_error;

	/* ipq 구조체에 새로 받은 sk_buff의 내용을 저장 */
	if (dev)
		qp->iif = dev->ifindex;

	qp->q.stamp = skb->tstamp;
	qp->q.mono_delivery_time = skb->mono_delivery_time;
	qp->q.meat += skb->len;
	qp->ecn |= ecn;
	add_frag_mem_limit(qp->q.fqdir, skb->truesize);
	
	// 패킷에서 처음 들어온 fragment면 처음 들어왔다는 플래그 표시
	if (offset == 0)
		qp->q.flags |= INET_FRAG_FIRST_IN;

```


```c title=inet_frag_queue_insert()
int inet_frag_queue_insert(struct inet_frag_queue *q, struct sk_buff *skb,
			   int offset, int end)
{
	struct sk_buff *last = q->fragments_tail;

	/* RFC5722, Section 4, amended by Errata ID : 3089
	 *                          When reassembling an IPv6 datagram, if
	 *   one or more its constituent fragments is determined to be an
	 *   overlapping fragment, the entire datagram (and any constituent
	 *   fragments) MUST be silently discarded.
	 *
	 * Duplicates, however, should be ignored (i.e. skb dropped, but the
	 * queue/fragments kept for later reassembly).
	 */
	if (!last)
		fragrun_create(q, skb);  /* First fragment. */
	else if (FRAG_CB(last)->ip_defrag_offset + last->len < end) {
		/* This is the common case: skb goes to the end. */
		/* Detect and discard overlaps. */
		if (offset < FRAG_CB(last)->ip_defrag_offset + last->len)
			return IPFRAG_OVERLAP;
		if (offset == FRAG_CB(last)->ip_defrag_offset + last->len)
			fragrun_append_to_last(q, skb);
		else
			fragrun_create(q, skb);
	} else {
		/* Binary search. Note that skb can become the first fragment,
		 * but not the last (covered above).
		 */
		struct rb_node **rbn, *parent;

		rbn = &q->rb_fragments.rb_node;
		do {
			struct sk_buff *curr;
			int curr_run_end;

			parent = *rbn;
			curr = rb_to_skb(parent);
			curr_run_end = FRAG_CB(curr)->ip_defrag_offset +
					FRAG_CB(curr)->frag_run_len;
			if (end <= FRAG_CB(curr)->ip_defrag_offset)
				rbn = &parent->rb_left;
			else if (offset >= curr_run_end)
				rbn = &parent->rb_right;
			else if (offset >= FRAG_CB(curr)->ip_defrag_offset &&
				 end <= curr_run_end)
				return IPFRAG_DUP;
			else
				return IPFRAG_OVERLAP;
		} while (*rbn);
		/* Here we have parent properly set, and rbn pointing to
		 * one of its NULL left/right children. Insert skb.
		 */
		fragcb_clear(skb);
		rb_link_node(&skb->rbnode, parent, rbn);
		rb_insert_color(&skb->rbnode, &q->rb_fragments);
	}

	FRAG_CB(skb)->ip_defrag_offset = offset;

	return IPFRAG_OK;
}
EXPORT_SYMBOL(inet_frag_queue_insert);
```

Red-Black 트리 구조로 fragment들을 관리함
- inet_frag_queue 구조체가 비어있으면 노드 새로 생성(`fragrun_create()`)
- skbuff 구조체에서 ipfrag_skb_cb 구조체 포인터를 들고 와서 새로운 fragment의 끝 위치가 마지막 fragment의 끝 위치보다 더 뒤에 있을 때
```c
/* Use skb->cb to track consecutive/adjacent fragments coming at
 * the end of the queue. Nodes in the rb-tree queue will
 * contain "runs" of one or more adjacent fragments.
 *
 * Invariants:
 * - next_frag is NULL at the tail of a "run";
 * - the head of a "run" has the sum of all fragment lengths in frag_run_len.
 */
struct ipfrag_skb_cb {
	union {
		struct inet_skb_parm	h4;
		struct inet6_skb_parm	h6;
	};
	struct sk_buff		*next_frag;
	int			frag_run_len;
	int			ip_defrag_offset;
};
#define FRAG_CB(skb)		((struct ipfrag_skb_cb *)((skb)->cb))
```

- 
	- 새로운 fragment의 시작 위치가 마지막 fragment 끝 위치보다 앞에 있으면 겹침(`IPFRAG_OVERLAP`)
	- 시작 위치가 끝이랑 바로 이어지면 그대로 붙임(`fragrun_append_to_last(q, skb)`)
	- 새로운 fragment의 시작 위치가 마지막 fragment의 끝 위치보다 뒤에 떨어져 있다면 새 run을 만듦
- 새로운 fragment의 끝 위치가 마지막 fragment의 끝 위치보다 더 앞에 있다면(중간에 삽입되어야 한다면)
	- 이진 탐색으로 rbtree에서 삽입 위치를 탐색
	- 중복 시 `IPFRAG_DUP`반환
	- 위치가 겹친다면 `IPFRAG_OVERLAP`반환
- 정상적이라면 삽입(
- ```c
		/* Here we have parent properly set, and rbn pointing to
		 * one of its NULL left/right children. Insert skb.
		 */
		fragcb_clear(skb); // skb->cd 구조체의 멤버들 초기화
		rb_link_node(&skb->rbnode, parent, rbn); // rbtree 연결
		rb_insert_color(&skb->rbnode, &q->rb_fragments); // 색깔 계산
  ```
---
**f. fragment 크기 계산 및 갱신, 최대 fragment 크기 계산**
```c
	fragsize = skb->len + ihl;

	if (fragsize > qp->q.max_size)
		qp->q.max_size = fragsize;

	if (ip_hdr(skb)->frag_off & htons(IP_DF) &&
	    fragsize > qp->max_df_size)
		qp->max_df_size = fragsize;
```
- fragsize: 새로운 fragment의 전체 길이
- 만약 전체 길이가 fragment 큐의 원소 중 최대 길이보다 크다면 최대 길이를 수정한다
- IP 헤더가 더 이상 fragment를 만들지 못하게 설정되어있고, 새로운 fragment의 전체 길이가 기존의 fragment를 만들지 못하는 최대 길이보다 크다면 수정한다.
---
**e. fragment 결합 검사 후 결합 시도**
```c
if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
    qp->q.meat == qp->q.len) {
	unsigned long orefdst = skb->_skb_refdst;

	skb->_skb_refdst = 0UL;
	err = ip_frag_reasm(qp, skb, prev_tail, dev);
	skb->_skb_refdst = orefdst;
	if (err)
		inet_frag_kill(&qp->q);
	return err;
}
```
- 첫번째와 마지막 fragment가 도작했고, 수신받은 fragment 데이터 길이(`qp->q.meat`)가 전체 데이터 길이(`qp->q.len`)와 일치한다면
	- 모든 fragment들을 합침(`ip_frag_reasm()`) 합치는 도중에는 `_skb_refdsk` 변수를 `(unsigned long)0`으로 바꿈
	- 오류 발생 시 해당 fragment 큐를 삭제

```c title=ip_frag_reasm()

/* Build a new IP datagram from all its fragments. */
static int ip_frag_reasm(struct ipq *qp, struct sk_buff *skb,
			 struct sk_buff *prev_tail, struct net_device *dev)
{
	struct net *net = qp->q.fqdir->net;
	struct iphdr *iph;
	void *reasm_data;
	int len, err;
	u8 ecn;
	
	// ipq가 필요없으니 제거
	ipq_kill(qp);
	
	// ECN(Explicit Congestion Notification) 
	ecn = ip_frag_ecn_table[qp->ecn];
	if (unlikely(ecn == 0xff)) {
		err = -EINVAL;
		goto out_fail;
	}

	/* Make the one we just received the head. */
	reasm_data = inet_frag_reasm_prepare(&qp->q, skb, prev_tail);
	if (!reasm_data)
		goto out_nomem;

	// 전체 재조립된 데이터그램의 길이 계산
	len = ip_hdrlen(skb) + qp->q.len;
	err = -E2BIG;
	if (len > 65535)
		goto out_oversize;

	inet_frag_reasm_finish(&qp->q, skb, reasm_data,
			       ip_frag_coalesce_ok(qp));

	skb->dev = dev;
	IPCB(skb)->frag_max_size = max(qp->max_df_size, qp->q.max_size);

	iph = ip_hdr(skb);
	iph->tot_len = htons(len);
	iph->tos |= ecn;

	/* When we set IP_DF on a refragmented skb we must also force a
	 * call to ip_fragment to avoid forwarding a DF-skb of size s while
	 * original sender only sent fragments of size f (where f < s).
	 *
	 * We only set DF/IPSKB_FRAG_PMTU if such DF fragment was the largest
	 * frag seen to avoid sending tiny DF-fragments in case skb was built
	 * from one very small df-fragment and one large non-df frag.
	 */
	if (qp->max_df_size == qp->q.max_size) {
		IPCB(skb)->flags |= IPSKB_FRAG_PMTU;
		iph->frag_off = htons(IP_DF);
	} else {
		iph->frag_off = 0;
	}

	ip_send_check(iph);

	__IP_INC_STATS(net, IPSTATS_MIB_REASMOKS);
	qp->q.rb_fragments = RB_ROOT;
	qp->q.fragments_tail = NULL;
	qp->q.last_run_head = NULL;
	return 0;

out_nomem:
	net_dbg_ratelimited("queue_glue: no memory for gluing queue %p\n", qp);
	err = -ENOMEM;
	goto out_fail;
out_oversize:
	net_info_ratelimited("Oversized IP packet from %pI4\n", &qp->q.key.v4.saddr);
out_fail:
	__IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
	return err;
}
```
---
**g. 재조립되지 않은 경우**
```c
	skb_dst_drop(skb);
	skb_orphan(skb);
	return -EINPROGRESS;
```

```c
// include/net/dst.h
/**
 * skb_dst_drop - drops skb dst
 * @skb: buffer
 *
 * Drops dst reference count if a reference was taken.
 */
 // skb가 참조하는 목적지(dst_entry) 참조를 해체
static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->_skb_refdst) {
		refdst_drop(skb->_skb_refdst);
		skb->_skb_refdst = 0UL;
	}
}

// 목적지 참조 카운트를 사용한다면 참조 카운트를 감소
static inline void refdst_drop(unsigned long refdst)
{
	if (!(refdst & SKB_DST_NOREF))
		dst_release((struct dst_entry *)(refdst & SKB_DST_PTRMASK));
}

// dst_entry.__rcuref.refcnt를 감소시킴(rcuref_put())
// 카운트가 0이라면 메모리를 해제하는 함수(dst_destroy_rcu())를 실행
void dst_release(struct dst_entry *dst)
{
	if (dst && rcuref_put(&dst->__rcuref))
		call_rcu_hurry(&dst->rcu_head, dst_destroy_rcu);
}
EXPORT_SYMBOL(dst_release);
```


```c title=skb_orphan()
// include/linux/skbuff.h
/*
 * @sk: Socket we are owned by
 * @destructor: Destruct function
 */
 struct sk_buff {
	struct sock		*sk;
	void		(*destructor)(struct sk_buff *skb);
;}

/**
 *	skb_orphan - orphan a buffer
 *	@skb: buffer to orphan
 *
 *	If a buffer currently has an owner then we call the owner's
 *	destructor function and make the @skb unowned. The buffer continues
 *	to exist but is no longer charged to its former owner.
 */
static inline void skb_orphan(struct sk_buff *skb)
{
	if (skb->destructor) {
		skb->destructor(skb);
		skb->destructor = NULL;
		skb->sk		= NULL;
	} else {
		BUG_ON(skb->sk);
	}
}
```