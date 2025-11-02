---
Parameter:
- void *
- void __user *
- unsigned long
Return:
- unsigned long
Location:
- /include/linux/uaccess.h
---
``` c title=copy_from_user()
static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (check_copy_size(to, n, false))
		n = _copy_from_user(to, from, n);
	return n;
}
```

[[copy_to_iter()]]와 구조상 동일하다. 
`check_copy_size()`함수에 전달하는 false 매개변수는 user 영역에서 커널 영역으로 들고 옴을 의미한다.


[[check_copy_size()]]
[[_copy_from_user()]]



