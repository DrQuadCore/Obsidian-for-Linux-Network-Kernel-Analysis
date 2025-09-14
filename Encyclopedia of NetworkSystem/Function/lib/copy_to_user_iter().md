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