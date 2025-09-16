```c
void __sk_flush_backlog(struct sock *sk)
{
	spin_lock_bh(&sk->sk_lock.slock);
	__release_sock(sk);

	if (sk->sk_prot->release_cb)
		INDIRECT_CALL_INET_1(sk->sk_prot->release_cb,
				     tcp_release_cb, sk);

	spin_unlock_bh(&sk->sk_lock.slock);
}
```

`release_sock()`과 동일한 방식으로 백로그를 처리한다. 소켓에 대기중인 프로세스를 깨우는 부분만 없다

[[__release_sock()]]
[[tcp_release_cb()]]
