```c
int __sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,
                 struct sockaddr __user *addr,  int addr_len)
{
        struct socket *sock;
        struct sockaddr_storage address;
        int err;
        struct msghdr msg;
		
		// a
        err = import_ubuf(ITER_SOURCE, buff, len, &msg.msg_iter);
        
        if (unlikely(err))
                return err;

        CLASS(fd, f)(fd);
        if (fd_empty(f))
                return -EBADF;
        // b 
        sock = sock_from_file(fd_file(f));
        if (unlikely(!sock))
                return -ENOTSOCK;

        msg.msg_name = NULL;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_namelen = 0;
        msg.msg_ubuf = NULL;
        
        
        // c
        //sendto 같이 addr이 NULL이 아닌 경우
        if (addr) {
                err = move_addr_to_kernel(addr, addr_len, &address);
                if (err < 0)
                        return err;
                msg.msg_name = (struct sockaddr *)&address;
                msg.msg_namelen = addr_len;
        }
        
        //flag 설정
        flags &= ~MSG_INTERNAL_SENDMSG_FLAGS;
        if (sock->file->f_flags & O_NONBLOCK)
                flags |= MSG_DONTWAIT;
        msg.msg_flags = flags;
        return __sock_sendmsg(sock, &msg);
}         
```

- a 부분
```c
	// a
	err = import_ubuf(ITER_SOURCE, buff, len, &msg.msg_iter);
```
- msg_iter 멤버 초기화를 위한 함수. 여기서 ITER_SOURCE는 1로 정의돼 있다.
```c title=/include/linux/uio.h
#define ITER_SOURCE	1	// == WRITE
#define ITER_DEST	0	// == READ
```
 [[import_ubuf()]]

---
- b부분
```c
		// b 
        sock = sock_from_file(fd_file(f));
```

```c
struct socket *sock_from_file(struct file *file)
{
	//파일이 소켓 파일인지 체크(주소 검사)
	if (likely(file->f_op == &socket_file_ops))
		//file->private_data를 반환
		return file->private_data;	

	return NULL;
}
```
- 조건문에서 파일이 소켓 파일인지 체크하고 file->private_data를 반환한다.
- file->private_data는 소켓을 생성하면서 파일과 소켓을 연결할 때 정해진다.
  [[sock_alloc_file()]]
- 결국 반환하는 것은 파일과 연결된 struct socket  이다.

---
- c부분
```c
        // c
        //sendto 같이 addr이 NULL이 아닌 경우
        if (addr) {
                err = move_addr_to_kernel(addr, addr_len, &address);
                if (err < 0)
                        return err;
                msg.msg_name = (struct sockaddr *)&address;
                msg.msg_namelen = addr_len;
        }
```

```c
int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (ulen == 0)
		return 0;
	if (copy_from_user(kaddr, uaddr, ulen))
		return -EFAULT;
	return audit_sockaddr(ulen, kaddr);
}
```
- socket의 주소를 kernel space로 복사한다. 이는 addr이 NULL 이 아닌 sendto() 를 사용할 때 호출된다.

[[__sock_sendmsg()]]