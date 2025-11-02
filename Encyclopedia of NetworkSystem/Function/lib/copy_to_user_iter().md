---
Parameter: 
- void __user *
- size_t
- size_t
- void *
- void *
Return:
- size_t
Location:
- /lib/iov_iter.c
---
```c title=copy_to_user_iter()
static __always_inline
size_t copy_to_user_iter(void __user *iter_to, size_t progress,
			 size_t len, void *from, void *priv2)
{
	if (should_fail_usercopy())
		return len;
	if (access_ok(iter_to, len)) {
		from += progress;
		instrument_copy_to_user(iter_to, from, len);
		len = raw_copy_to_user(iter_to, from, len);
	}
	return len;
}
```

> `access_ok()` 함수로 해당 주소가 유저 영역에서 유효한지 검사 후 `raw_copy_to_user()`로 메모리에 접근하여 복사 수행
---
### raw_copy_to_user()
**/include/asm-generic/uaccess.h**
```c title=raw_copy_to_user()
static inline __must_check unsigned long
raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	memcpy((void __force *)to, from, n);
	return 0;
}
```

- from: 복사할 메모리 주소. 커널 영역에 있는 패킷을 가리킴
- to: 복사를 받을 메모리 주소. 유저 영역에 있는 ubuf를 가리킴

**/arch/x86/include/asm/uaccess_64.h
```c
static __always_inline __must_check unsigned long
raw_copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	return copy_user_generic((__force void *)dst, src, size);
}
```

user 영역의 메모리 주소인 *dst*를 `__force void *`로 캐스팅하여 복사 수행(이제 user영역과 커널 영역을 구분하지 않음)

```c title=copy_user_generic()
static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned long len)
{
	stac(); //userspace 접근 허용
	/*
	 * If CPU has FSRM feature, use 'rep movs'.
	 * Otherwise, use rep_movs_alternative.
	 */
	asm volatile(
		"1:\n\t"
		ALTERNATIVE("rep movsb",
			    "call rep_movs_alternative", ALT_NOT(X86_FEATURE_FSRM))
		"2:\n"
		_ASM_EXTABLE_UA(1b, 2b)
		:"+c" (len), "+D" (to), "+S" (from), ASM_CALL_CONSTRAINT
		: : "memory", "rax");
	clac(); // userspace 접근 차단
	return len;
}
```