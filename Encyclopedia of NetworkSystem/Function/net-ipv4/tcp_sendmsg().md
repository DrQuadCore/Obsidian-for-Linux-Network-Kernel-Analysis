---
Parameter:
- sock *
- msghdr *
- size_t
Reture:
- int
Location:
- /net/ipv4/tcp.c
---
```c title=tcp_sendmsg()
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
        int ret;

        lock_sock(sk);
        ret = tcp_sendmsg_locked(sk, msg, size);
        release_sock(sk);

        return ret;
}
```

- net/ipv4/tcp.c에 구현되어있습니다.
- sk에 대해 lock을 획득하고 tcp_sendmsg_locked() 함수를 호출합니다.

[[tcp_sendmsg_locked()]]