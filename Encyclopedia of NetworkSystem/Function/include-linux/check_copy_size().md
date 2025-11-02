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

- `__builtin_object_size()`로 컴파일 타임에 크기를 알 수 있다면 addr의 크기를 가져와 bytes와 비교한 후 addr이 작다면 false를 반환
	https://www.ibm.com/docs/en/xl-c-and-cpp-linux/16.1.0?topic=functions-builtin-object-size
- copy할 바이트 수가 int값의 범위를 넘어간다면 false 반환
- 아니면 `check_object_size()`로 런타임에 addr의 경계를 검사

---
### check_object_size()
```c title=check_object_size()
// include/linux/thread_info.h
static __always_inline void check_object_size(const void *ptr, unsigned long n, bool to_user)
{
	if (!__builtin_constant_p(n))
		__check_object_size(ptr, n, to_user);
}
```
- `__builtin_constant_p()`: n이 상수인지 판단하는 매크로?

---
### `__check_object_size()`
```c title=__check_object_size()
// mm/usercopy.c
/*
 * Validates that the given object is:
 * - not bogus address
 * - fully contained by stack (or stack frame, when available)
 * - fully within SLAB object (or object whitelist area, when available)
 * - not in kernel text
 */
void __check_object_size(const void *ptr, unsigned long n, bool to_user)
{
	if (static_branch_unlikely(&bypass_usercopy_checks))
		return;

	/* Skip all tests if size is zero. */
	if (!n)
		return;

	/* Check for invalid addresses. */
	// ptr 주소가 이상하면 abort
	check_bogus_address((const unsigned long)ptr, n, to_user);

	/* Check for bad stack object. */
	// 복사하려는 영역이 스택에 없는지, 정상적인지, 중간에 걸쳤는지로 분기
	switch (check_stack_object(ptr, n)) {
	case NOT_STACK:
		/* Object is not touching the current process stack. */
		break;
	case GOOD_FRAME:
	case GOOD_STACK:
		/*
		 * Object is either in the correct frame (when it
		 * is possible to check) or just generally on the
		 * process stack (when frame checking not available).
		 */
		return;
	default:
		usercopy_abort("process stack", NULL, to_user,
#ifdef CONFIG_ARCH_HAS_CURRENT_STACK_POINTER
			IS_ENABLED(CONFIG_STACK_GROWSUP) ?
				ptr - (void *)current_stack_pointer :
				(void *)current_stack_pointer - ptr,
#else
			0,
#endif
			n);
	}

	/* Check for bad heap object. */
	// 힙 영역인 경우 잘못되었으면 abort
	check_heap_object(ptr, n, to_user);

	/* Check for object in kernel to avoid text exposure. */
	check_kernel_text_object((const unsigned long)ptr, n, to_user);
}
EXPORT_SYMBOL(__check_object_size);
```

>각 경우에서 메모리 주소`ptr`에서 `n`만큼 들고 왔을 때 정상적인지 검사하고, 잘못되었을 시 `usercopy_abort()` 함수로 복사를 중단함
- `check_bogus_address()`: 주소가 유효한지 검사
	- Wrapped Address: *ptr*에서 *n*만큼 가져오면 오버플로우로 주소가 줄어드는지 검사하여 *ptr + n - 1 < ptr*이라면 abort
	- *ptr*이 NULL 또는 0이라면 abort
- `check_stack_object()`: 스택인 경우 검사
	- 스택의 시작 주소, 끝 주소를 들고 와서 *ptr*과 *ptr + n - 1*의 주소와 비교함
	- 스택 바깥에 있다면(`case NOT_STACK:`) 다음 검사로 넘어가고, 
	- 모두 스택 안에 있다면(`case GOOD_STACK:`) 정상적으로 종료
	- 스택 가장자리에 걸쳐있다면(`defalut:`) abort
- `check_heap_object()`: 커널에서 동적 메모리 할당되었을 경우 확인
	- kmap이면 페이지 공간을 벗어났는지 검사
	- vmalloc이면 `vmap_area`구조체로 분리된 

