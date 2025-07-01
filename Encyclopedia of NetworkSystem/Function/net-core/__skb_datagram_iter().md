```C
static int __skb_datagram_iter(const struct sk_buff *skb, int offset,
			       struct iov_iter *to, int len, bool fault_short,
			       size_t (*cb)(const void *, size_t, void *,
					    struct iov_iter *), void *data)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset, start_off = offset, n;
	struct sk_buff *frag_iter;

	/* Copy header. */
	if (copy > 0) {
		if (copy > len)
			copy = len;
		n = INDIRECT_CALL_1(cb, simple_copy_to_iter,
				    skb->data + offset, copy, data, to);
		offset += n;
		if (n != copy)
			goto short_copy;
		if ((len -= copy) == 0)
			return 0;
	}

	/* Copy paged appendix. Hmm... why does this look so complicated? */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		WARN_ON(start > offset + len);

		end = start + skb_frag_size(frag);
		if ((copy = end - offset) > 0) {
			struct page *page = skb_frag_page(frag);
			u8 *vaddr = kmap(page);

			if (copy > len)
				copy = len;
			n = INDIRECT_CALL_1(cb, simple_copy_to_iter,
					vaddr + skb_frag_off(frag) + offset - start,
					copy, data, to);
			kunmap(page);
			offset += n;
			if (n != copy)
				goto short_copy;
			if (!(len -= copy))
				return 0;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			if (__skb_datagram_iter(frag_iter, offset - start,
						to, copy, fault_short, cb, data))
				goto fault;
			if ((len -= copy) == 0)
				return 0;
			offset += copy;
		}
		start = end;
	}
	if (!len)
		return 0;

	/* This is not really a user copy fault, but rather someone
	 * gave us a bogus length on the skb.  We should probably
	 * print a warning here as it may indicate a kernel bug.
	 */

fault:
	iov_iter_revert(to, offset - start_off);
	return -EFAULT;

short_copy:
	if (fault_short || iov_iter_count(to))
		goto fault;

	return 0;
}
```

>`copy_from_iter`, `copy_page_from_iter`, `skb_copy_datagram_from_iter`의 함수들을 통해 각각 skb, frags, frag list에서 데이터를 복사해가는 모습을 볼 수 있다. 또한 frag list 에서 다시 재귀적으로 `skb_copy_datagram_iter()`를 호출하는 것을 볼 수 있었다.