```c
static int ep_poll_callback(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	int pwake = 0;
	unsigned long flags;
	struct epitem *epi = ep_item_from_wait(wait);
	struct eventpoll *ep = epi->ep;

	if ((unsigned long)key & POLLFREE) {
		ep_pwq_from_wait(wait)->whead = NULL;
		/*
		 * whead = NULL above can race with ep_remove_wait_queue()
		 * which can do another remove_wait_queue() after us, so we
		 * can't use __remove_wait_queue(). whead->lock is held by
		 * the caller.
		 */
		list_del_init(&wait->task_list);
	}

	spin_lock_irqsave(&ep->lock, flags);

	/*
	 * If the event mask does not contain any poll(2) event, we consider the
	 * descriptor to be disabled. This condition is likely the effect of the
	 * EPOLLONESHOT bit that disables the descriptor when an event is received,
	 * until the next EPOLL_CTL_MOD will be issued.
	 */
	 //disable인 경우 리턴
	if (!(epi->event.events & ~EP_PRIVATE_BITS))
		goto out_unlock;

	/*
	 * Check the events coming with the callback. At this stage, not
	 * every device reports the events in the "key" parameter of the
	 * callback. We need to be able to handle both cases here, hence the
	 * test for "key" != NULL before the event match test.
	 */
	if (key && !((unsigned long) key & epi->event.events))
		goto out_unlock;

	/*
	 * If we are transferring events to userspace, we can hold no locks
	 * (because we're accessing user memory, and because of linux f_op->poll()
	 * semantics). All the events that happen during that period of time are
	 * chained in ep->ovflist and requeued later on.
	 */
	 //epoll이 유저공간에 이벤트 복사 중일 시 임시로 ovflist에 묶어둠
	if (unlikely(ep->ovflist != EP_UNACTIVE_PTR)) {
		if (epi->next == EP_UNACTIVE_PTR) {
			epi->next = ep->ovflist;
			ep->ovflist = epi;
			if (epi->ws) {
				/*
				 * Activate ep->ws since epi->ws may get
				 * deactivated at any time.
				 */
				__pm_stay_awake(ep->ws);
			}

		}
		goto out_unlock;
	}

	/* If this file is already in the ready list we exit soon */
	//타겟 fd의 epitem이 아직 없으면 추가
	if (!ep_is_linked(&epi->rdllink)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);
		__pm_stay_awake(epi->ws);
	}

	/*
	 * Wake up ( if active ) both the eventpoll wait list and the ->poll()
	 * wait list.
	 */
	 //잠든 task 깨움
	if (waitqueue_active(&ep->wq))
		wake_up_locked(&ep->wq);
	//자신도 wake
	if (waitqueue_active(&ep->poll_wait))
		pwake++;
//lock해제 후 safewake
out_unlock:
	spin_unlock_irqrestore(&ep->lock, flags);

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return 1;
}
```
[^1]: 
```c
static inline struct epitem *ep_item_from_wait(wait_queue_t *p)
{
	return container_of(p, struct eppoll_entry, wait)->base;
}
```

```c
struct eppoll_entry {
    struct wait_queue_entry wait;  // 실제 fd waitqueue에 붙는 엔트리
    struct epitem *base;           // 연결된 epitem
    struct wait_queue_head *whead; // 어느 waitqueue에 붙었는지
    struct list_head llink;        // epitem->pwqlist에 연결하는 링크
};
```

```c
static inline struct eppoll_entry *ep_pwq_from_wait(wait_queue_t *p){	
	return container_of(p, struct eppoll_entry, wait);
}
```