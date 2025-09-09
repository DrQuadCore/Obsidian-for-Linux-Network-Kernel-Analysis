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
```c title=sock_recvmsg()
/**
 *	sock_recvmsg - receive a message from @sock
 *	@sock: socket
 *	@msg: message to receive
 *	@flags: message flags
 *
 *	Receives @msg from @sock, passing through LSM. Returns the total number
 *	of bytes received, or an error.
 */
int sock_recvmsg(struct socket *sock, struct msghdr *msg, int flags)
{
	int err = security_socket_recvmsg(sock, msg, msg_data_left(msg), flags);

	return err ?: sock_recvmsg_nosec(sock, msg, flags);
}
EXPORT_SYMBOL(sock_recvmsg);
```

먼저 `security_socket_recvmsg()`함수를 호출해 수신받은 메시지의 권한을 확인한다.
권한이 있다면(`err==0`) [[sock_recvmsg_nosec()]]을 실행한다.