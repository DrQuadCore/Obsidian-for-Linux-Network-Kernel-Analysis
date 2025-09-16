```c title=lock_sock()
static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}
```


```c title=lock_sock_nested()
void lock_sock_nested(struct sock *sk, int subclass)
{
	/* The sk_lock has mutex_lock() semantics here. */
	mutex_acquire(&sk->sk_lock.dep_map, subclass, 0, _RET_IP_);

	might_sleep();
	spin_lock_bh(&sk->sk_lock.slock);
	if (sock_owned_by_user_nocheck(sk))
		__lock_sock(sk);   // [[__lock_sock()]]
	sk->sk_lock.owned = 1;
	spin_unlock_bh(&sk->sk_lock.slock);
}
EXPORT_SYMBOL(lock_sock_nested);
```

- softirq를 비활성화하고 스핀 락을 잡음
- 소켓이 사용자 공간에서 사용 중인지 확인하고 사용 중이라면 `__lock_sock()` 함수로 대기
- 소켓을 소유하게 되면 스핀 락을 해제하고 함수 종료

