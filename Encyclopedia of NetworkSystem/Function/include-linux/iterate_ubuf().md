```c title=iterate_ubuf()
/*
 * Handle ITER_UBUF.
 */
static __always_inline
size_t iterate_ubuf(struct iov_iter *iter, size_t len, void *priv, void *priv2,
		    iov_ustep_f step)
{
	void __user *base = iter->ubuf;
	size_t progress = 0, remain;

	remain = step(base + iter->iov_offset, 0, len, priv, priv2);
	progress = len - remain;
	iter->iov_offset += progress;
	iter->count -= progress;
	return progress;
}
```
- base: ubuf가 시작하는 유저 영역의 메모리 주소
- remain: 데이터 카피를 하고 남은 바이트 수
- progress: 데이터 카피가 완료된 바이트 수
- iter->iov_offset: 다음 데이터 카피를 시작할 ubuf 내의 오프셋

> 데이터 카피를 할 유저 영역의 메모리 주소 시작점을 계산하고, `step`에 저장된 함수를 실행한다. (`copy_to_user_iter()`)
> 

[[copy_to_user_iter()]]
