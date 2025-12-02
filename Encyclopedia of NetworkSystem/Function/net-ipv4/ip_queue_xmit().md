---
Parameter:
  - sock
  - sk_buff
  - flowi4
Return: int
Location: /net/ipv4/ip_input.c
---

```c
int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)
{
	return __ip_queue_xmit(sk, skb, fl, READ_ONCE(inet_sk(sk)->tos)); // ToS 정보 추가해서 다음 함수로
}
```

TCP에서 만든 skb를 IP 레이어로 전달하기 위한 entry point 역할 

[[__ip_queue_xmit()]]