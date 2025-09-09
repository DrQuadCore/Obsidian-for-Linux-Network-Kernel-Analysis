---
Parameter:
  - int
  - void __user
  - size_t
  - unsigned int
  - sockaddr __user
  - int __user
Return:
  - int
Location:
  - /net/socket.c
---
```c title=__sys_recvfrom()

/*
 *	Receive a frame from the socket and optionally record the address of the
 *	sender. We verify the buffers are writable and if needed move the
 *	sender address from kernel to user space.
 */
int __sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
		   struct sockaddr __user *addr, int __user *addr_len)
{
	struct sockaddr_storage address;// 커널 내부에서 주소 저장용
	struct msghdr msg = {
		// 송신자 주소가 필요하다면 address에 기록, 아니면 NULL
		/* Save some cycles and don't copy the address if not needed */
		.msg_name = addr ? (struct sockaddr *)&address : NULL,
	};
	struct socket *sock;
	int err, err2;
	int fput_needed;
	
	// 유저 영역의 버퍼 ubuf를 커널의 msg.msg_iter로 가져오기
	err = import_ubuf(ITER_DEST, ubuf, size, &msg.msg_iter);
	if (unlikely(err))
		return err;
	// fd로 소켓 구조체 찾기
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	// 소켓에서 데이터 가져오기
	err = sock_recvmsg(sock, &msg, flags);

	// 송신자 주소가 필요하다면 유저 영역으로 복사
	if (err >= 0 && addr != NULL) {
		err2 = move_addr_to_user(&address,
					 msg.msg_namelen, addr, addr_len);
		if (err2 < 0)
			err = err2;
	}

	fput_light(sock->file, fput_needed);
out:
	return err;
}
```

``` c
SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
		unsigned int, flags, struct sockaddr __user *, addr,
		int __user *, addr_len)
{
	return __sys_recvfrom(fd, ubuf, size, flags, addr, addr_len);
}

```
- `__user`: 유저 공간의 메모리 주소임을 나타냄.
- 논블로킹(`O_NONBLOCK`):

> 전달받은 패킷을 관리하는 `msghdr` 구조체를 만든다.
> 유저 영역의 메모리 공간에 있는 버퍼를 커널로 가져오고, `msg.msg_iter`에 저장한다.
> `sockfd_lookup_light()` 함수로 주어진 fd에 매핑된 소켓(`socket`)을 찾고, 이 소켓에서 패킷을 가져오는 함수 `sock_recvmsg()`로 소켓과, msghdr를 전달한다.
> 만약 송신자의 주소가 `recv()` 시스템 콜에서 주어졌다면 `move_addr_to_user()` 함수로 주소를 유저 영역으로 전달한다.


