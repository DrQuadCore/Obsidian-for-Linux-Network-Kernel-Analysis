```c
/**
 * skb_try_coalesce - try to merge skb to prior one
 * @to: prior buffer
 * @from: buffer to add
 * @fragstolen: pointer to boolean
 * @delta_truesize: how much more was allocated than was requested
 */
bool skb_try_coalesce(struct sk_buff *to, struct sk_buff *from,
		      bool *fragstolen, int *delta_truesize)
{
	struct skb_shared_info *to_shinfo, *from_shinfo;
	int i, delta, len = from->len;

	*fragstolen = false;

	if (skb_cloned(to))
		return false;

	/* In general, avoid mixing page_pool and non-page_pool allocated
	 * pages within the same SKB. In theory we could take full
	 * references if @from is cloned and !@to->pp_recycle but its
	 * tricky (due to potential race with the clone disappearing) and
	 * rare, so not worth dealing with.
	 */
	if (to->pp_recycle != from->pp_recycle)
		return false;
	//important
	if (len <= skb_tailroom(to)) {
		if (len)
			BUG_ON(skb_copy_bits(from, 0, skb_put(to, len), len));
		*delta_truesize = 0;
		return true;
	}

	to_shinfo = skb_shinfo(to);
	from_shinfo = skb_shinfo(from);
	if (to_shinfo->frag_list || from_shinfo->frag_list)
		return false;
	if (skb_zcopy(to) || skb_zcopy(from))
		return false;

	if (skb_headlen(from) != 0) {
		struct page *page;
		unsigned int offset;

		if (to_shinfo->nr_frags +
		    from_shinfo->nr_frags >= MAX_SKB_FRAGS)
			return false;

		if (skb_head_is_locked(from))
			return false;

		delta = from->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));

		page = virt_to_head_page(from->head);
		offset = from->data - (unsigned char *)page_address(page);

		//important
		skb_fill_page_desc(to, to_shinfo->nr_frags,
				   page, offset, skb_headlen(from));
		*fragstolen = true;
	} else {
		if (to_shinfo->nr_frags +
		    from_shinfo->nr_frags > MAX_SKB_FRAGS)
			return false;

		delta = from->truesize - SKB_TRUESIZE(skb_end_offset(from));
	}

	WARN_ON_ONCE(delta < len);

	memcpy(to_shinfo->frags + to_shinfo->nr_frags,
	       from_shinfo->frags,
	       from_shinfo->nr_frags * sizeof(skb_frag_t));
	to_shinfo->nr_frags += from_shinfo->nr_frags;

	if (!skb_cloned(from))
		from_shinfo->nr_frags = 0;

	/* if the skb is not cloned this does nothing
	 * since we set nr_frags to 0.
	 */
	if (skb_pp_frag_ref(from)) {
		for (i = 0; i < from_shinfo->nr_frags; i++)
			__skb_frag_ref(&from_shinfo->frags[i]);
	}

	to->truesize += delta;
	to->len += len;
	to->data_len += len;

	*delta_truesize = delta;
	return true;
}
```

pkt들을 합치는 함수이다. to skb에다 from skb를 합친다. 
to skb는 sk backlog에 가장 마지막 skb이고 from skb는 backlog에 올리고자하는 skb이다.
skb들이 clone된 상태거나, frag_list를 가지고 있거나 zero copy가 된 경우에는 합치지 못한다.
만약 to skb에 공간이 충분하다면
`if (len <= skb_tailroom(to)) {`
`BUG_ON(skb_copy_bits(from, 0, skb_put(to, len), len));`
to 에 data를 옮겨주고 리턴한다.

공간이 부족한 경우, from skb의 frag들을 to skb로 이동시켜주는 방식으로 합친다.
from skb의 fragment들을 to skb frags[]에다 memcpy해준다. 

`skb_fill_page_desc(to, to_shinfo->nr_frags, page, offset, skb_headlen(from));`
위의 함수로 from skb의 head에 존재하는 data를 to skb의 page로 넣는다.
to skb가 nr_frags 번째 frag가 page 안의 skb_headlen(from)만큼의 데이터를 offset에서 부터 가르키게 만든다. 

to skb의 true size를 업데이트 해준다. 