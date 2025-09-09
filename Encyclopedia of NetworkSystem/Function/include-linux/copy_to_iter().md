---
Parameter:
- void *
- size_t
- iov_iter *
Return:
- size_t
Location:
- /include/linux/uio.h
---

```c
size_t copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i)
{
	if (check_copy_size(addr, bytes, true))
		return _copy_to_iter(addr, bytes, i);
	return 0;
}
```

[[check_copy_size()]]함수로 addr의 크기가 bytes보다 큰지 확인한다.