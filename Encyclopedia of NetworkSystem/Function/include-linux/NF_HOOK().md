---
Parameter:
  - uint8_t
  - unsigned int
  - net
  - sock
  - sk_buff
  - net_device
  - net_device_
  - int (*okfn)(struct net *, struct sock *, struct sk_buff *)
Return: int
Location: /include/linux/netfilter.h
---
``` c  
static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
	if (ret == 1)
		ret = okfn(net, sk, skb);
	return ret;
}
```

>여기는 CONFIG_NETFILTER 조건이 true일 때 활성화 된다.
>우선 `nf_hook()`함수를 호출해주고 만약 `ret`이 1이라면 그제서야 `okfn()`을 실행하게 된다.
- pf : protocol family 
- hook : 후킹 값 중 하나 (NF_INET_PRE_ROUTING, .... )
- net : network namespace
- sk : socket
- in : 입력 네트워크 장치
- out : 출력 네트워크 장치
- okfn : 훅이 종료되면 호출될 함수의 포인터

넷필터 훅을 등록하는 매크로이다. 
nf_hook() 함수를 실행하고 리턴값이 있으면 okfn() 함수를 실행한다.
okfn은 call back function으로 ip_rcv_finish() 함수이다.

넷필터 훅은 리눅스 네트워크 스택에서 패킷이 지나가는 여러 시점에 연결되어 네트워크 모듈이 패킷을 처리할 수 있게 하는 인터페이스이다. 이 훅을 통해 패킷이 들어올 때, 라우팅될 때, 나갈 때 등을 감지할 수 있으며, 이 시점에 패킷을 허용, 수정, 차단, 또는 다른 경로로 전송하는 등의 작업을 할 수 있다. 주로 방화벽, 패킷 필터링, NAT(Network Address Transition)에서 사용된다. 
ip_rcv 과정에서 넷필터 훅을 거치는 이유는 패킷을 수신할 때, 방화벽 규칙, NAT(Network Address Transition), 패킷 필터링 등을 적용하기 위함이다. 

[[nf_hook()_]]
[[ip_rcv_finish()]]