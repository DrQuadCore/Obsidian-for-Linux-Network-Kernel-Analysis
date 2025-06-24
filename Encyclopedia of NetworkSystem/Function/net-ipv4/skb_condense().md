```c
/**
 * skb_condense - try to get rid of fragments/frag_list if possible
 * @skb: buffer
 *
 * Can be used to save memory before skb is added to a busy queue.
 * If packet has bytes in frags and enough tail room in skb->head,
 * pull all of them, so that we can free the frags right now and adjust
 * truesize.
 * Notes:
 *	We do not reallocate skb->head thus can not fail.
 *	Caller must re-evaluate skb->truesize if needed.
 */
void skb_condense(struct sk_buff *skb)
{
	if (skb->data_len) {
		if (skb->data_len > skb->end - skb->tail ||
		    skb_cloned(skb))
			return;

		/* Nice, we can free page frag(s) right now */
		__pskb_pull_tail(skb, skb->data_len);
	}
	/* At this point, skb->truesize might be over estimated,
	 * because skb had a fragment, and fragments do not tell
	 * their truesize.
	 * When we pulled its content into skb->head, fragment
	 * was freed, but __pskb_pull_tail() could not possibly
	 * adjust skb->truesize, not knowing the frag truesize.
	 */
	skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
}
```