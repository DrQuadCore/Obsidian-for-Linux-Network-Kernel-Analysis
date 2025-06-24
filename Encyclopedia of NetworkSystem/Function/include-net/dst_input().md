---
Parameter:
  - sk_buff
Return: int
Location: /include/net/dst.h
---
```c title=dst_input코드
static inline int dst_input(struct sk_buff *skb)
{
	return INDIRECT_CALL_INET(skb_dst(skb)->input,
				  ip6_input, ip_local_deliver, skb);
}
```

>간단하게 `INDIRECT_CALL_INET` 함수 매크로를 호출하는 코드이다. 여기서도 ip 버전에 따라서 간접적으로 함수 호출이 이루어지게 된다. 여기서 중요하게 봐야할 것은 `dst_input`함수 그자체이다. `dst_output`함수도 존재하며, 똑같이 `INDIRECT_CALL_INET` 함수 매크로를 호출하게 된다. 둘의 차이점은 `dst_entry`라는 구조체를 바탕으로 처리되는 것들이다.
>`dst_entry`는 패킷을 처리하는데 네트워크 경로에 대한 정보를 저장하는 구조체이다. `skb` 구조체 안에 포인터로 가르키고 있으며, `input`과 `output` 함수 포인터를 가지고 있다. 각각 패킷이 입력될 때와 출력될 때 호출되는 함수들이다.

[[ip_local_deliver()]]
