```c title=__lock_sock()
void __lock_sock(struct sock *sk)
	__releases(&sk->sk_lock.slock)
	__acquires(&sk->sk_lock.slock)
{
	DEFINE_WAIT(wait);

	for (;;) {
		prepare_to_wait_exclusive(&sk->sk_lock.wq, &wait,
					TASK_UNINTERRUPTIBLE);
		spin_unlock_bh(&sk->sk_lock.slock);
		schedule();// 다른 프로세스에게 양보
		spin_lock_bh(&sk->sk_lock.slock);
		if (!sock_owned_by_user(sk)) // 소켓이 사용 중이지 않는다면
			break;
	}
	finish_wait(&sk->sk_lock.wq, &wait);
}
```

- 무한 반복문을 돌면서 스핀 락을 해제하고 CPU를 다른 프로세스에게 양보한다
- 이후 현재 프로세스가 스케줄되면 다시 락을 잡고 소켓이 아직도 사용 중인지 확인하고 사용 중이지 않다면 반복문을 종료한다