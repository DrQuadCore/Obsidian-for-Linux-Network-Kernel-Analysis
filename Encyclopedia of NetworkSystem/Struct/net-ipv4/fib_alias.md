---
Location: /net/ipv4/fib_lookup.h
---
```c
struct fib_alias {
	struct hlist_node	fa_list;
	struct fib_info		*fa_info; // [[fib_info]]
	dscp_t			fa_dscp;
	u8			fa_type; // route타입
	u8			fa_state; // 상태 flag (active/dead)
	u8			fa_slen; // suffix length
	u32			tb_id;
	s16			fa_default;
	u8			offload;
	u8			trap;
	u8			offload_failed;
	struct rcu_head		rcu;
};
```

같은 목적지를 공유하는 여러 routing entry를 묶어서 관리하기 위해 만들어진 구조체이다. 라우팅 정보 fib_info는 공유하고, 서로 다른 값만 별로도 alias에 저장해 둔다.

이전 커널 버전에서는 fib_alias 구조체에 tos 멤버도 있었다. 지금은 사라졌지만, fib_alias를 이해하는데 도움이 될 것 같은데

다음과 같이 destination address는 같은데 tos만 다른 경우, 단순히 라우팅 엔트리를 3개 만드는 게 아니라 fib_alias를 세 개 만들어서 

```c
ip route add 192.168.1.10 via 192.168.2.1 tos 0x2 
ip route add 192.168.1.10 via 192.168.2.1 tos 0x4 
ip route add 192.168.1.10 via 192.168.2.1 tos 0x6
```

이런 식으로 같은 fib_info를 가리키게 하고 alias의 tos 값만 다르게 저장한다.

[[Pasted Image 20251202004435_371.png]]
