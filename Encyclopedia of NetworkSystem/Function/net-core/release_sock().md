```C
void release_sock(struct sock *sk)
{
	spin_lock_bh(&sk->sk_lock.slock);
	if (sk->sk_backlog.tail)
		__release_sock(sk);

	if (sk->sk_prot->release_cb)
		INDIRECT_CALL_INET_1(sk->sk_prot->release_cb,
				     tcp_release_cb, sk);

	sock_release_ownership(sk);
	if (waitqueue_active(&sk->sk_lock.wq))
		wake_up(&sk->sk_lock.wq);
	spin_unlock_bh(&sk->sk_lock.slock);
}
```

- `spin_lock_bh()` 함수로 스핀 락을 잡고, softirq가 처리되지 않게 함
- `sock`의 백로그에 패킷이 존재한다면 `__release_sock()` 함수로 패킷 처리
- 프로토콜 별 release callback 호출
- `waitqueue_active()` 함수로 대기 중인 프로세스가 있는지 확인 후 소켓 락을 기다리는 프로세스 깨움
- 스핀 락 해제

[[__release_sock()]]
[[tcp_release_cb()]]