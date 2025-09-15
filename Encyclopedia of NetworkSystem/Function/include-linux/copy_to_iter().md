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

[[check_copy_size()]]함수로 addr의 크기가 bytes보다 큰지 확인하고, `_copy_to_iter()`함수로 다음 과정 진행

---
### `_copy_to_iter()`
- /lib/iov_iter.c에 있음
```c title=_copy_to_iter()
size_t _copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i)
{
	if (WARN_ON_ONCE(i->data_source))
		return 0;
	if (user_backed_iter(i))
		might_fault();
	return iterate_and_advance(i, bytes, (void *)addr,
				   copy_to_user_iter, memcpy_to_iter);
}
EXPORT_SYMBOL(_copy_to_iter);
```

- iov_iter->data_source가 true라면 0 반환
- iov_iter->iter_type이 ITER_UBUF이거나 ITER_IOVEC이라면 `might_fault()`로 페이지 폴트 준비
```c title=user_backed_iter()
  static inline bool user_backed_iter(const struct iov_iter *i)
{
	return iter_is_ubuf(i) || iter_is_iovec(i);
}
  ```
- `iterate_and_advance()` 함수에 두 함수 `copy_to_user_iter()`, `memcpy_to_iter()` 넣고 다음 작업으로 넘어감

[[iterate_and_advance()]]