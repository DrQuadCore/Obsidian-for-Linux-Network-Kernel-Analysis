### 1. 폴링 시, backlog 인지 판단하는 방법
[[net_dev_init()]]
```

	for_each_possible_cpu(i) {
	
		...
		init_gro_hash(&sd->backlog);
		sd->backlog.poll = process_backlog;
		sd->backlog.weight = weight_p;		
		...

	}
```

- 위는 net_dev_init() 함수 내의 softnet_data 초기화 부분이다. 여기서 backlog napi struct는 poll 함수 포인터가 process_backlog를 가리키도록 설정함을 확인할 수 있다.
  이로 인해 `__napi_poll()` 함수 내에서 napi_struct->poll() 함수를 호출할 때 
  backlog napi_struct인지 q_vector의 napi_struct인지 따로 판단할 필요가 없고 현재 napi_struct의 poll() 함수 포인터가 가리키는  함수를 그대로 호출하면 된다.
  
- 이는 고유의 softnet_data의 backlog napi struct의 poll() 함수 포인터를 매핑하는 과정이고, 
  q_vector의 napi_struct에서 poll() 함수 포인터를 `ice_napi_poll()` 함수로 매핑하는 것은 q vector의 메모리 할당을 할 때 이루어진다. 

[[ice_vsi_alloc_q_vector()]] 65번 라인의 `netif_napi_add()` 함수 참고


-----
### 2. RPS 과정에서 다른 softnet_data에 skb를 추가하는 방법
- napi_struct 에는 GRO가 끝난 skb를 연결 리스트로 저장하는 list_head 타입의 rx_list가 존재한다. 
  [[gro_normal_one()]]
  
- RPS 과정에서는 다른 CPU의 softnet_data에 skb를 전달하게 된다. 
  [[enqueue_to_backlog()]]
  enqueue_to_backlog() 함수 안에서 `__skb_queue_tail()` 함수를 호출한다. 여기서 타겟 CPU의 softnet_data 속 input_pkt_queue에 skb를 연결한다. 이때 연결하는 단위는 skb 1개씩 연결한다.

- softnet_data 안의 input_pkt_queue의 타입은 sk_buff_head 이다. 이 구조체는 여러 개의 sk_buff를 연결하는 원형 연결 리스트의 헤드 노드이다.
  
```
struct sk_buff_head {
	/* These two members must be first to match sk_buff. */
	struct_group_tagged(sk_buff_list, list,
		struct sk_buff	*next;
		struct sk_buff	*prev;
	);

	__u32		qlen;
	spinlock_t	lock;
};
```


```
static inline void __skb_queue_tail(struct sk_buff_head *list,
				   struct sk_buff *newsk)
{
	__skb_queue_before(list, (struct sk_buff *)list, newsk);
}
```

```
static inline void __skb_queue_before(struct sk_buff_head *list,
				      struct sk_buff *next,
				      struct sk_buff *newsk)
{
	__skb_insert(newsk, ((struct sk_buff_list *)next)->prev, next, list);
}
```

```
static inline void __skb_insert(struct sk_buff *newsk,
				struct sk_buff *prev, struct sk_buff *next,
				struct sk_buff_head *list)
{
	/* See skb_queue_empty_lockless() and skb_peek_tail()
	 * for the opposite READ_ONCE()
	 */
	WRITE_ONCE(newsk->next, next);
	WRITE_ONCE(newsk->prev, prev);
	WRITE_ONCE(((struct sk_buff_list *)next)->prev, newsk);
	WRITE_ONCE(((struct sk_buff_list *)prev)->next, newsk);
	WRITE_ONCE(list->qlen, list->qlen + 1);
}
```

- `__skb_queue_tail()` 함수는 연달아서 `__skb_queue_before()` , `__skb_insert()` 를 호출한다. 최종적인 `__skb_insert()` 함수 내부에서는 헤드 노드라고 할 수 있는 list의 이전 노드를 새롭게 추가할 skb의 이전 노드로 설정하고 연결한다.
  즉, 현재 연결 리스트의 마지막 노드에 새로운 skb를 연결하는 구조이다. 
  
- 이후, backlog napi struct가 스케줄링이 되고 나서 backlog napi_struct를 폴링할 때, backlog_process() 함수를 호출한다. 
	[[process_backlog()]]
  
  이 함수 내부에서 현재 input_pkt_queue 안에 들어있는 skb 리스트를 softnet_data 안의 process_queue 옮긴다.
  이전의 skb를 연결하는 것과 차이점은 skb 1개의 단위가 아니라 sk_buff_head 자체를 이용해서 연결 리스트 2개를 그대로 연결하게 된다. 

