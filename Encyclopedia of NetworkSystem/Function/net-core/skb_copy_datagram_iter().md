```C
/**
 *	skb_copy_datagram_iter - Copy a datagram to an iovec iterator.
 *	@skb: buffer to copy
 *	@offset: offset in the buffer to start copying from
 *	@to: iovec iterator to copy to
 *	@len: amount of data to copy from buffer to iovec
 */
int skb_copy_datagram_iter(const struct sk_buff *skb, int offset,
			   struct iov_iter *to, int len)
{
	trace_skb_copy_datagram_iovec(skb, len);
	return __skb_datagram_iter(skb, offset, to, len, false,
			simple_copy_to_iter, NULL);
}
```

[[__skb_datagram_iter()]]
