---
Parameter:
- socket *
- msghdr *
- size_t
Return:
- int
Location:
- net/ipv4/af_inet.c
---
```c title=inet_sendmsg()
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	if (unlikely(inet_send_prepare(sk)))
		return -EAGAIN;

	return INDIRECT_CALL_2(sk->sk_prot->sendmsg, tcp_sendmsg, udp_sendmsg,
						   sk, msg, size); // [[tcp_sendmsg()]]
}
```
- net/ipv4/af_inet.c에 구현되어있습니다.
- inet_send_prepare()를 통해 소켓이 전송 가능한 상태인지 검사합니다.
- 매크로 함수를 통해 프로토콜에 따른 sendmsg 함수를 호출합니다.
	- tcp는 tcp_sendmsg()를, udp는 udp_sendmsg()를 호출합니다.
---
### inet_send_prepare()
```c title=inet_send_prepare()
// net/ipv4/af_inet.c
int inet_send_prepare(struct sock *sk)
{
	sock_rps_record_flow(sk); // [[sock_rps_record_flow()]]

	/* We may need to bind the socket. */
	if (data_race(!inet_sk(sk)->inet_num) && !sk->sk_prot->no_autobind &&
	    inet_autobind(sk))
		return -EAGAIN;

	return 0;
}
EXPORT_SYMBOL_GPL(inet_send_prepare)
```
- RPS flow를 기록합니다.
- sk에 port가 바인딩되어있지 않다면 자동으로 port를 바인딩합니다.
 ```c
  if (data_race(!inet_sk(sk)->inet_num) && // 소켓에 포트 번호가 할당되지 않는다면
		   !sk->sk_prot->no_autobind && // 소켓 프로토콜이 자동 바인드를 허용한다면
	    inet_autobind(sk)) // 자동 바인드 시도
	    return -EAGAIN; // 자동 바인드 실패 시 오류 반환
	    
	return 0; // 정상 소켓임 확인
  ```

---
### inet_autobind()
```c inet_au
```
 [[sock_rps_record_flow()]]
 [[tcp_sendmsg()]]