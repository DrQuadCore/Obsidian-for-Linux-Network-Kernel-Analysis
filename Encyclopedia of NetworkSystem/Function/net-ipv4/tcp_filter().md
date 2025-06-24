---
Parameter:
  - sock
  - sk_buff
Return: int
Location: /net/ipv4/tcp_ipv4.c
---
```c
int tcp_filter(struct sock *sk, struct sk_buff *skb)
{
    struct tcphdr *th = (struct tcphdr *)skb->data;
  
    return sk_filter_trim_cap(sk, skb, th->doff * 4);
}
```

>tcp 헤더를 가져와서 `sk_filter_trim_cap()`함수의 return값을 반환하게 된다. 자세한 역할은 `tcp_v4_rcv()`의 본문에 포함되어 있다.