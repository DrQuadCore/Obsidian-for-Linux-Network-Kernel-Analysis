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
	int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn); // [[nf_hook()_]]]
	if (ret == 1)
		ret = okfn(net, sk, skb); // [[ip_rcv_finish()]]
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

[[nf_hook()_]]
[[ip_rcv_finish()]]

---
넷필터는 리눅스 네트워크 스택에서 패킷이 지나가는 여러 시점에 연결되어 네트워크 모듈이 hook point에서 패킷을 가로채 원하는 대로 처리할 수 있게 하는 인터페이스이다. 이 hook을 통해 패킷이 들어올 때, 라우팅될 때, 나갈 때 등을 감지할 수 있으며, 이 시점에 패킷을 허용, 수정, 차단, 또는 다른 경로로 전송하는 등의 작업을 할 수 있다. 주로 방화벽, 패킷 필터링, NAT(Network Address Transition)에서 사용된다. 

ip_rcv 과정에서 넷필터 hook을 거치는 이유는 패킷을 수신할 때, 방화벽 규칙, NAT(Network Address Transition), 패킷 필터링 등을 적용하기 위함이다. 

```c
// NF_HOOK 호출 함수 
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	...
	...
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
					net, NULL, skb, dev, NULL,
					ip_rcv_finish);
}
```

`NF_INET_PRE_ROUTING` hook은 패킷이 내부 라우팅 엔진으로 전달되기 전에 네트워크 계층에서 거치게 되는 hook이다. 위 코드에서는 해당 hook 지점에 등록된 hook 함수 체인(hook_head)을 순차적으로 실행한다. (nf_hook으로)

참고로 netfilter hook의 반환 값은 다음 중 하나이다.

```c
/* Responses from hook functions. */
#define NF_DROP 0 // 패킷 폐기
#define NF_ACCEPT 1 // 커널 네트워크 스택에서 계속 이동
#define NF_STOLEN 2 // hook 함수가 pkt 소유권 가져감 (네트워크 스택 따라 이동 X)
#define NF_QUEUE 3 // userspace로 전달
#define NF_REPEAT 4 // 동일한 hook 함수 다시 실행
#define NF_STOP 5	/* Deprecated, for userspace nf_queue compatibility. */
#define NF_MAX_VERDICT NF_STOP
```

여기서는 반환값이 1(== NF_ACCEPT)이면, `ip_rcv_finish()` 함수를 호출한다.
