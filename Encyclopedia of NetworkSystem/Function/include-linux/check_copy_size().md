---
Parameter: 
- void *
- size_t
- bool
Return:
- bool
Location:
- /include/linux/thread_info.h
---

```c
static __always_inline __must_check bool
check_copy_size(const void *addr, size_t bytes, bool is_source)
{
	int sz = __builtin_object_size(addr, 0);
	if (unlikely(sz >= 0 && sz < bytes)) {
		if (!__builtin_constant_p(bytes))
			copy_overflow(sz, bytes);
		else if (is_source)
			__bad_copy_from();
		else
			__bad_copy_to();
		return false;
	}
	if (WARN_ON_ONCE(bytes > INT_MAX))
		return false;
	check_object_size(addr, bytes, is_source);
	return true;
}
```

- `__builtin_object_size()`로 addr의 크기를 가져와 bytes와 비교한 후 addr이 작다면 false를 반환
- copy할 바이트 수가 int값의 범위를 넘어간다면 false 반환
- 아니면 `check_object_size()`로 ???