---
Parameter:
  - napi_struct
  - list_head
Return: int
Location: /net/core/dev.c
---

```c title=napi_poll()
static int napi_poll(struct napi_struct *n, struct list_head *repoll)
{
	bool do_repoll = false;
	void *have;
	int work;

	list_del_init(&n->poll_list); // [[Encyclopedia of NetworkSystem/Function/include-linux/list_del_init() .md|list_del_init()]]

	have = netpoll_poll_lock(n);

	work = __napi_poll(n, &do_repoll); // [[Encyclopedia of NetworkSystem/Function/net-core/__napi_poll().md|__napi_poll()]]

	if (do_repoll)
		list_add_tail(&n->poll_list, repoll); // [[Encyclopedia of NetworkSystem/Function/include-linux/list_add_tail().md|list_add_tail()]]

	netpoll_poll_unlock(have);

	return work;
}
```

[[Encyclopedia of NetworkSystem/Function/include-linux/list_del_init() .md|list_del_init()]]
[[Encyclopedia of NetworkSystem/Function/net-core/__napi_poll().md|__napi_poll()]]
[[Encyclopedia of NetworkSystem/Function/include-linux/list_add_tail().md|list_add_tail()]]

> poll_list를 지우고, netpoll_poll_lock을 걸게 된다.(멀티 코어 환경 대응) 이후 `__napi_poll()` 함수를 실행시켜서 폴링을 시작하게 된다. 또한 추가적으로 다시 폴링이 필요하다면 `list_add_tail`을 통해 repoll 변수에 저장된 리스트를 가져오게 된다.