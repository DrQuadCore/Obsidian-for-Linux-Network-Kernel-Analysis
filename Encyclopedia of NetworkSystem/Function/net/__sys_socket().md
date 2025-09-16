---
Parameter:
- int

- int_
- int__

Return:

- int

Location: /net/socket.c
---
```c title=__sys_socket()
int __sys_socket(int family, int type, int protocol)
{
	struct socket *sock;
	int flags;

	sock = __sys_socket_create(family, type,
				   update_socket_protocol(family, type, protocol));
				   // [[__sys_socket_create()]]
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	flags = type & ~SOCK_TYPE_MASK;
	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
	// [[sock_map_fd()]]
}
```

```c
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	return __sys_socket(family, type, protocol);
}
```

 - `socket()` 시스템 콜의 결과로 해당 함수가 실행된다.
 - `__sys_socket_create()` 함수를 호출해 소켓을 만든다.
 - type에서 flag만을 추출하고, include/linux/net.h에서 정의된 `SOCK_NONBLOCK` 옵션이 커널의 옵션값인 `O_NONBLOCK` 과 다르다면 flag에서 전자를 제거하고 후자를 설정한다.
 - `sock_map_fd()` 함수를 호출해 socket 구조체와 파일 디스크립터를 매핑한다.

[[__sys_socket_create()]]
sock_map_fd()