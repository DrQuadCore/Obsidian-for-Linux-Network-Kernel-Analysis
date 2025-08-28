# epoll
역할: 여러 파일 디스크립터의 상태를 커널이 감지해, 준비된 것들을 유저 공간에 알려주는 이벤트 디멀티플렉서이다.

```c
struct eventpoll {
	/* Protect the access to this structure */
	spinlock_t lock;

	/*
	 * This mutex is used to ensure that files are not removed
	 * while epoll is using them. This is held during the event
	 * collection loop, the file cleanup path, the epoll file exit
	 * code and the ctl operations.
	 */
	struct mutex mtx;

	/* Wait queue used by sys_epoll_wait() */
	//epoll_wait()호출한 task sleep
	wait_queue_head_t wq;

	/* Wait queue used by file->poll() */
	//다른 epoll에게 감시 당할 때 외부 epoll의 waitqueue entry
	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	struct list_head rdllist;

	/* RB tree root used to store monitored fd structs */
	//fd 집합
	struct rb_root rbr;

	/*
	 * This is a single linked list that chains all the "struct epitem" that
	 * happened while transferring ready events to userspace w/out
	 * holding ->lock.
	 */
	struct epitem *ovflist;

	/* wakeup_source used when ep_scan_ready_list is running */
	//suspend방지
	struct wakeup_source *ws;

	/* The user that created the eventpoll descriptor */
	struct user_struct *user;

	struct file *file;

	/* used to optimize loop detection check */
	int visited;
	struct list_head visited_list_link;
};
```

1. epoll 인스턴스 생성 [[epoll_create1()]]
2. 관심 FD 등록/수정/삭제 [[epoll_ctl()]]
3. task sleep & wakeup -> userspace전달 [[epoll_wait()]]