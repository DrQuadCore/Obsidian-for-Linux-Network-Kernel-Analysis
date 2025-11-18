---
Parameter:
- socket
- msghdr
- size_t
- int
Return:
- int
Location:
- /net/ipv4/af_inet.c
---


```c title=inet_recvmsg()
int inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		 int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	int err;

	// a. rps에 플로우 기록하기
	if (likely(!(flags & MSG_ERRQUEUE)))
		sock_rps_record_flow(sk);

	// b. 다음 레이어로 이동
	err = INDIRECT_CALL_2(sk->sk_prot->recvmsg, tcp_recvmsg, udp_recvmsg,
			      sk, msg, size, flags, &addr_len);
	if (err >= 0)
		msg->msg_namelen = addr_len;
	return err;
}
EXPORT_SYMBOL(inet_recvmsg);
```

**a. rps에 플로우 기록하기**
```
#define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue */
```
소켓이 소켓 오류 큐에서 오류를 받아오지 않는다면, `sock_rps_record_flow()`함수로 이 플로우가 현재 CPU에서 진행되고 있음을 기록

**b. 다음 레이어로 이동**
 - `sock` 구조체 내부에는 소켓 계층에서 Transport 계층으로의 프로토콜을 정의한 `proto` 구조체를 가지고 있다. 정확히는  `(struct sock *)sk->(struct sock_common)__sk_common.(struct proto *)skc_prot` 형태로 참조한다.
	 - [[tcp_recvmsg()]]
 - `INDIRECT_CALL_2` 매크로로 tcp인지, udp인지에 따라 대응하는 함수를 실행하고, 정상적으로 종료되었다면 전달받은 `addr_len` 정수값을 `msghdr` 구조체에 기록한다.
 
```c
/**
  *	struct sock - network layer representation of sockets
  * @__sk_common: shared layout with inet_timewait_sock
  */
struct sock {
	struct sock_common	__sk_common;
	...
#define sk_prot			__sk_common.skc_prot
...
}

/**
 *	struct sock_common - minimal network layer representation of sockets
 * @skc_prot: protocol handlers inside a network family
 */
struct sock_common {
	...
	struct proto		*skc_prot;
	...
}

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 */
struct proto {
	...
	int			(*recvmsg)(struct sock *sk, struct msghdr *msg,
					   size_t len, int flags, int *addr_len);
	...
}
```

[[sock_rps_record_flow()]]
[[tcp_recvmsg()]]
