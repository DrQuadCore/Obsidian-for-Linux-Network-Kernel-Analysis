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

[[__release_sock()]]

