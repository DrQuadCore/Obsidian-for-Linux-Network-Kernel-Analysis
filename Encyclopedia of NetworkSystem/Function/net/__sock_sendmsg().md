

```c title=__sock_sendmsg
static int __sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
	// 다른 소켓으로 msg를 보낼 수 있는 지 검사
	int err = security_socket_sendmsg(sock, msg,
					  msg_data_left(msg));

	return err ?: sock_sendmsg_nosec(sock, msg);
}
```
- security_socket_sendmsg() 함수로 socket의 보안정책을 체크한다. err이 0이 아니라면 정상이라는 뜻으로 sock_sendmsg_nosec() 함수를 호출한다.

---
- /security/security.c 경로
```c title=security_socket_sendmsg()
/**
 * security_socket_sendmsg() - Check if sending a message is allowed
 * @sock: sending socket
 * @msg: message to send
 * @size: size of message
 *
 * Check permission before transmitting a message to another socket.
 *
 * Return: Returns 0 if permission is granted.
 */
int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return call_int_hook(socket_sendmsg, sock, msg, size);
}
```
- call_int_hook 함수를 호출해 보안 훅 함수를 호출한다.
  
```c title=call_int_hook()
#define call_int_hook(HOOK, ...)					\
({									\
	__label__ OUT;							\
	// RC값을 default값인 0으로 설정
	int RC = LSM_RET_DEFAULT(HOOK);					\
									\
	// 보안정책 검사
	LSM_LOOP_UNROLL(__CALL_STATIC_INT, RC, HOOK, OUT, __VA_ARGS__);	\
OUT:									\
	RC;								\
})
```

```
#define LSM_LOOP_UNROLL(M, ...) 		\
do {						\
	// 보안 모듈의 개수인 MAX_LSM_COUNT 만큼 반복해서 보안 정책 검사
	UNROLL(MAX_LSM_COUNT, M, __VA_ARGS__)	\
} while (0)
```


```c
#define UNROLL(N, MACRO, args...) CONCATENATE(__UNROLL_, N)(MACRO, args)

#define __UNROLL_0(MACRO, args...)
#define __UNROLL_1(MACRO, args...)  __UNROLL_0(MACRO, args)  MACRO(0, args)
#define __UNROLL_2(MACRO, args...)  __UNROLL_1(MACRO, args)  MACRO(1, args)
...
```
- \_\_UNROLL() 함수에서 보안모듈의 개수만큼 \_\_CALL_STATIC_INT() 를 호출해 검사를 수행한다.

```c
#define __CALL_STATIC_INT(NUM, R, HOOK, LABEL, ...)			     \
do {									     \
	if (static_branch_unlikely(&SECURITY_HOOK_ACTIVE_KEY(HOOK, NUM))) {  \
		// 보안 검사 수행
		R = static_call(LSM_STATIC_CALL(HOOK, NUM))(__VA_ARGS__);    \
		// 디폴트 값이었던 0이 아닐 경우 OUT으로 이동하고 에러코드 반환
		if (R != LSM_RET_DEFAULT(HOOK))				     \
			goto LABEL;					     \
	}								     \
} while (0);
```
- static_call() 함수를 통해 보안 검사를 수행한다.
- default값이었던 0이 아닐 경우 LABEL로 이동한다. 여기서 LABEL은 call_int_hook() 함수 안의 OUT 이다. 따라서 RC값을 반환하고 정상이 아닐 경우 RC 값이 0이 아니고  정상이라면 0을 반환하는 것을 알 수 있다.
  
---

```c title=sock_sendmsg_nosec
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
	int ret = INDIRECT_CALL_INET(READ_ONCE(sock->ops)->sendmsg, inet6_sendmsg,
				     inet_sendmsg, sock, msg,
				     msg_data_left(msg));
	BUG_ON(ret == -EIOCBQUEUED);

	if (trace_sock_send_length_enabled())
		call_trace_sock_send_length(sock->sk, ret, 0);
	return ret;
}
```

- 매크로 함수를 통해 IP 버전에 따라 알맞은 inet_sendmsg() 또는 inet6_sendmsg() 함수를 호출한다.
- ipv4는  inet_sendmsg() 를 호출한다.

[[inet_sendmsg()]]
