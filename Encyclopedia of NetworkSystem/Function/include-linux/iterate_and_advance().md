---
Parameter:
- iov_iter *
- size_t
- void *
- iov_ustep_f
- iov_step_f
Return:
- size_t
Location:
- /include/linux/iov_iter.h
---

```c title=iterate_and_advance()

typedef size_t (*iov_step_f)(void *iter_base, size_t progress, size_t len,
			     void *priv, void *priv2);
typedef size_t (*iov_ustep_f)(void __user *iter_base, size_t progress, size_t len,
			      void *priv, void *priv2);

/**
 * iterate_and_advance - Iterate over an iterator
 * @iter: The iterator to iterate over.
 * @len: The amount to iterate over.
 * @priv: Data for the step functions.
 * @ustep: Function for UBUF/IOVEC iterators; given __user addresses.
 * @step: Function for other iterators; given kernel addresses.
 *
 * As iterate_and_advance2(), but priv2 is always NULL.
 */
static __always_inline
size_t iterate_and_advance(struct iov_iter *iter, size_t len, void *priv,
			   iov_ustep_f ustep, iov_step_f step)
{
	return iterate_and_advance2(iter, len, priv, NULL, ustep, step);
}
```
NULL을 추가로 넘겨주면서 `iterate_and_advance2()` 함수로 넘어간다.
- iter: 반복자(이전 함수에서 `i` == `msg->iter` == `ubuf`)
- len: 반복하는 크기(이전 함수에서 `bytes`)
- priv: 시작하는 위치(이전 함수에서 `addr`)
- ustep: 유저 영역의 주소로 ubuf 또는 iovec 반복할 함수(`copy_to_user_iter()`)
- step: 커널영역의 주소로 반복할 함수(`memcpy_to_iter()`)

[[iterate_and_advance2()]]