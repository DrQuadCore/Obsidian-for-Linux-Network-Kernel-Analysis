---
Parameter:
  - iov_iter *
  - size_t
  - void *
  - void_ *
  - iov_ustep_f
  - iov_step_f
Return:
  - size_t
Location:
  - /include/linux/iov_iter.h
---
```c title=iterate_and_advance2()
/**
 * iterate_and_advance2 - Iterate over an iterator
 * @iter: The iterator to iterate over.
 * @len: The amount to iterate over.
 * @priv: Data for the step functions.
 * @priv2: More data for the step functions.
 * @ustep: Function for UBUF/IOVEC iterators; given __user addresses.
 * @step: Function for other iterators; given kernel addresses.
 *
 * Iterate over the next part of an iterator, up to the specified length.  The
 * buffer is presented in segments, which for kernel iteration are broken up by
 * physical pages and mapped, with the mapped address being presented.
 *
 * Two step functions, @step and @ustep, must be provided, one for handling
 * mapped kernel addresses and the other is given user addresses which have the
 * potential to fault since no pinning is performed.
 *
 * The step functions are passed the address and length of the segment, @priv,
 * @priv2 and the amount of data so far iterated over (which can, for example,
 * be added to @priv to point to the right part of a second buffer).  The step
 * functions should return the amount of the segment they didn't process (ie. 0
 * indicates complete processsing).
 *
 * This function returns the amount of data processed (ie. 0 means nothing was
 * processed and the value of @len means processes to completion).
 */
static __always_inline
size_t iterate_and_advance2(struct iov_iter *iter, size_t len, void *priv,
			    void *priv2, iov_ustep_f ustep, iov_step_f step)
{
	if (unlikely(iter->count < len))
		len = iter->count;
	if (unlikely(!len))
		return 0;

	if (likely(iter_is_ubuf(iter)))
		return iterate_ubuf(iter, len, priv, priv2, ustep);
	if (likely(iter_is_iovec(iter)))
		return iterate_iovec(iter, len, priv, priv2, ustep);
	if (iov_iter_is_bvec(iter))
		return iterate_bvec(iter, len, priv, priv2, step);
	if (iov_iter_is_kvec(iter))
		return iterate_kvec(iter, len, priv, priv2, step);
	if (iov_iter_is_xarray(iter))
		return iterate_xarray(iter, len, priv, priv2, step);
	return iterate_discard(iter, len, priv, priv2, step);
}
```

>이전 함수에서 priv2 = NULL인 상태로 실행되었다.
> 반복할 크기가 iter의 크기
> iter->iter_type에 따라서 적절한 함수를 실행한다. 

