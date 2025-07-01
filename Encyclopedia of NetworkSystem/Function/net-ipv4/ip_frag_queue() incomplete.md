```c
/* Add new segment to existing queue. */
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct net *net = qp->q.fqdir->net;
	int ihl, end, flags, offset;
	struct sk_buff *prev_tail;
	struct net_device *dev;
	unsigned int fragsize;
	int err = -ENOENT;
	SKB_DR(reason);
	u8 ecn;

	/* If reassembly is already done, @skb must be a duplicate frag. */
	if (qp->q.flags & INET_FRAG_COMPLETE) {
		SKB_DR_SET(reason, DUP_FRAG);
		goto err;
	}

	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}

	ecn = ip4_frag_ecn(ip_hdr(skb)->tos);
	offset = ntohs(ip_hdr(skb)->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);

	/* Determine the position of this fragment. */
	end = offset + skb->len - skb_network_offset(skb) - ihl;
	err = -EINVAL;

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

