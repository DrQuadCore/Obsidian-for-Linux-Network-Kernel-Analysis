---
Parameter:
- socket *
- int
Return:
- int
Location:
- /net/socket.c
---
```c title=sock_map_fd()
static int sock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;
	int fd = get_unused_fd_flags(flags);
	if (unlikely(fd < 0)) {
		sock_release(sock);
		return fd;
	}

	newfile = sock_alloc_file(sock, flags, NULL); // [[sock_alloc_file()]]
	if (!IS_ERR(newfile)) {
		fd_install(fd, newfile);
		return fd;
	}

	put_unused_fd(fd);
	return PTR_ERR(newfile);
}
```

- `get_unused_fd_flag()` 함수로 사용하지 않는 파일 디스크립터 번호를 할당받고, 만약 실패했다면(`fd < 0`) 소켓을 해제한다
- `struct socket` 구조체에 새로 만든 `struct file` 구조체를 연결한다. 성공했다면 파일 디스립터와 파일 구조체도 연결한다
- 파일 구조체를 만드는 데 실패했다면 파일 디스크립터를 반납하고 오류를 반환한다

[[sock_alloc_file()]]