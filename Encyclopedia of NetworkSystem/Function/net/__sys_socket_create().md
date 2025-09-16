```c title=__sys_socket_create()
static struct socket *__sys_socket_create(int family, int type, int protocol)
{
	struct socket *sock;
	int retval;
	
	// 상수값들이 동일한지 검증
	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

	// 매개변수로 받은 type이 유효한 플래그인지 확인
	if ((type & ~SOCK_TYPE_MASK) & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return ERR_PTR(-EINVAL);
	type &= SOCK_TYPE_MASK;
	
	// 소켓 생성
	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		return ERR_PTR(retval);

	return sock;
}
```

`socket_create()` 함수는 wrapper 함수로 `__socket_create()` 함수를 호출한다.

`__socket_create()` 함수에서 `security_socket_create(family, type, protocol, kern)`을 통해 보안을 검사하고 `sock_alloc()` 함수로 새로운 inode를 받아 `socket` 구조체와 연결한다

