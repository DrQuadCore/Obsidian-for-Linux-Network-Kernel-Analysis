---
Location:
  - /lib/iov_iter.c
---


```c title=import_ubuf()
int import_ubuf(int rw, void __user *buf, size_t len, struct iov_iter *i)
{
	if (len > MAX_RW_COUNT)
		len = MAX_RW_COUNT;
	if (unlikely(!access_ok(buf, len)))
		return -EFAULT;

	iov_iter_ubuf(i, rw, buf, len);
	return 0;
}
```

- `access_ok()` 함수로 해당 주소가 유저 영역에서 유효한지 검사한다. 이후에 msghdr의 iov_iter 구조체인 msg_iter를 초기화해주는 iov_iter_ubuf() 함수를 호출한다.

  
```c title=iov_iter_ubuf()
// include/linux/uio.h 경로

static inline void iov_iter_ubuf(struct iov_iter *i, unsigned int direction,
			void __user *buf, size_t count)
{
	WARN_ON(direction & ~(READ | WRITE));
	*i = (struct iov_iter) {
		.iter_type = ITER_UBUF,
		.data_source = direction, 
		.ubuf = buf,
		.count = count,
		.nr_segs = 1
	};
}
```