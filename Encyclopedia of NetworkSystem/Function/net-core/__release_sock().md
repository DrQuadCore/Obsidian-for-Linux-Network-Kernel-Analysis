---
Parameter: 
- sock *
Return:
- void
Location:
- /net/core/socket.c
---
```C title=__release_sock()
void __release_sock(struct sock *sk)
	__releases(&sk->sk_lock.slock)
	__acquires(&sk->sk_lock.slock)
{
	struct sk_buff *skb, *next;

	while ((skb = sk->sk_backlog.head) != NULL) {
		sk->sk_backlog.head = sk->sk_backlog.tail = NULL;

		spin_unlock_bh(&sk->sk_lock.slock);

		do {
			next = skb->next;
			prefetch(next);
			DEBUG_NET_WARN_ON_ONCE(skb_dst_is_noref(skb));
			skb_mark_not_on_list(skb);
			sk_backlog_rcv(sk, skb);

			cond_resched();

			skb = next;
		} while (skb != NULL);

		spin_lock_bh(&sk->sk_lock.slock); // bh: bottom-half
	}

	/*
	 * Doing the zeroing here guarantee we can not loop forever
	 * while a wild producer attempts to flood us.
	 */
	sk->sk_backlog.len = 0;
}
```

- 첫번째 while문
	- 백로그에서 첫번째 sk_buff를 들고 오고, 백로그의 시작과 끝을 NULL로 초기화하고 스핀락을 해제하여 softirq 과정에서 새로 백로그에 sk_buff를 추가할 수 있게 함
	- 두번째 do-while 문
		- `sk_backlog_rcv()` 함수로 프로토콜에 맞는 함수 실행
	- while문 종료 전 다시 스핀 락을 잡고 실행 도중 새로 백로그에 sk_buff가 들어왔는지 확인 후 반복