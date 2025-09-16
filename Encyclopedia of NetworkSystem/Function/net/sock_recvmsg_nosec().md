---
Parameter:
- socket
- msghdr
- int
Return:
- int
Location:
- /net/socket.c
---

```c title=sock_recvmsg_nosec()
static inline int sock_recvmsg_nosec(struct socket *sock, struct msghdr *msg,
				     int flags)
{
	int ret = INDIRECT_CALL_INET(READ_ONCE(sock->ops)->recvmsg,
				     inet6_recvmsg,
				     inet_recvmsg, sock, msg,
				     msg_data_left(msg), flags);
	if (trace_sock_recv_length_enabled())
		call_trace_sock_recv_length(sock->sk, ret, flags);
	return ret;
}
```

`socket` 구조체 내부에는 프로토콜에 맞는 함수들이 저장된 구조체 `proto_ops`가 있고, `INDIRECT_CALL_INET` 매크로를 통해 ipv4, ipv6인지에 따라 `sock->ops->recvmsg` 함수 포인터가 가리키는 함수(`inet6_recvmsg()` 또는 `inet_recvmsg()`)를 실행한다.

```c
// include/linux/net.h
/**
 *  struct socket - general BSD socket
 *  @ops: protocol specific socket operations
 */
struct socket {
	...
	const struct proto_ops	*ops; /* Might change with IPV6_ADDRFORM or MPTCP. */
	...
};
struct proto_ops {
	...
	/* Notes for implementing recvmsg:
	 * ===============================
	 * msg->msg_namelen should get updated by the recvmsg handlers
	 * iff msg_name != NULL. It is by default 0 to prevent
	 * returning uninitialized memory to user space.  The recvfrom
	 * handlers can assume that msg.msg_name is either NULL or has
	 * a minimum size of sizeof(struct sockaddr_storage).
	 */
	int		(*recvmsg)   (struct socket *sock, struct msghdr *m,
				      size_t total_len, int flags);
	...
```

[[inet_recvmsg()]]