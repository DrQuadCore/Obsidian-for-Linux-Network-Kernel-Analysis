``` c
SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;

	return sys_epoll_create1(0);
}
```
구버전 API(epoll_create)를 size만 체크하고 신버전 API(epoll_create1)로 넘김