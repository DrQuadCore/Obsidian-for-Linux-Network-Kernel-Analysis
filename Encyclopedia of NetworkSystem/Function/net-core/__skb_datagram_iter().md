```C
static int __skb_datagram_iter(const struct sk_buff *skb, int offset,
			       struct iov_iter *to, int len, bool fault_short,
			       size_t (*cb)(const void *, size_t, void *,
					    struct iov_iter *), void *data)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset, start_off = offset, n;
	struct sk_buff *frag_iter;

	// a. linear 영역 데이터 복사하기
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
	
	// b. skb_frag_t 복사하기
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

	// c. frag_list 순회하면서 추가 sk_buff 복사하기
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

>**a. 헤더 복사하기**
>skb->data의 데이터를 offset 이후부터 복사하여 `skb_headlen() - offset` 만큼만 복사한다.
>복사한 데이터만큼 offset, len을 변경한다.

> **b. skb_frag_t 복사하기**
> skb->skb_shard_info의 배열을 for문을 통해 순회하면서 각 page를 복사한다.
> 물리적 공간에 있는 `struct page *`를 가상 메모리 주소에 매핑하는 함수 `kmap()`로 가상 메리 주소를 구하고 복사를 수행한다.

> **c. frag_list 순회하면서 추가 sk_buff 복사하기**
> sk_buff에 추가적으로 연결된 다른 sk_buff를 재귀적으로 호출하여 복사한다.

[[simple_copy_to_iter()]]