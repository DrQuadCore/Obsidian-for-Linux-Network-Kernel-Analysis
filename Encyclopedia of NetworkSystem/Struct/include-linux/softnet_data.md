---
Location: /include/linux/netdevice.h
---

```c title=softnet_data구조체
struct softnet_data {
	struct list_head poll_list;
	struct sk_buff_head process_queue;
	  
	/* stats */
	unsigned int processed;
	unsigned int time_squeeze;
#ifdef CONFIG_RPS
	struct softnet_data *rps_ipi_list;
#endif
  
	bool in_net_rx_action;
	bool in_napi_threaded_poll;
  
#ifdef CONFIG_NET_FLOW_LIMIT
	struct sd_flow_limit __rcu *flow_limit;
#endif
	struct Qdisc *output_queue;
	struct Qdisc **output_queue_tailp;
	struct sk_buff *completion_queue;
#ifdef CONFIG_XFRM_OFFLOAD
	struct sk_buff_head xfrm_backlog;
#endif
	/* written and read only by owning cpu: */
	struct {
		u16 recursion;
		u8 more;
#ifdef CONFIG_NET_EGRESS
		u8 skip_txqueue;
#endif
	} xmit;
#ifdef CONFIG_RPS
	/* input_queue_head should be written by cpu owning this struct,
	* and only read by other cpus. Worth using a cache line.
	*/
	unsigned int input_queue_head ____cacheline_aligned_in_smp;
	  
	/* Elements below can be accessed between CPUs for RPS/RFS */
	call_single_data_t csd ____cacheline_aligned_in_smp;
	struct softnet_data *rps_ipi_next;
	unsigned int cpu;
	unsigned int input_queue_tail;
#endif
	unsigned int received_rps;
	unsigned int dropped;
	struct sk_buff_head input_pkt_queue;
	struct napi_struct backlog;
	  
	/* Another possibly contended cache line */
	spinlock_t defer_lock ____cacheline_aligned_in_smp;
	int defer_count;
	int defer_ipi_scheduled;
	struct sk_buff *defer_list;
	call_single_data_t defer_csd;
};
```

>설명으로 Incoming packets are placed on per-CPU queues라고 써져 있다.
>여기서 말하는 per-CPU queues가 `softnet_data`의 `poll_list`이다.

```c
/*
* Device drivers call our routines to queue packets here. We empty the
* queue in the local softnet handler.
*/
  
DEFINE_PER_CPU_ALIGNED(struct softnet_data, softnet_data);
EXPORT_PER_CPU_SYMBOL(softnet_data);
```

> 위의 코드는 `/net/core/dev.c`의 420번째 줄이다. 여기서 각 cpu마다 해당 타입의 변수를 선언하게 되며, 심볼 또한 전역적으로 쓸 수 있도록 Export하게 된다.
> [[Excalidraw/RPS-IPI 관계도.md#^JGjyIN93|softnet_data 도식화]]

>다음은 `net_dev_init()`함수이다. 이 함수는 OS 부팅시에 실행 되며, 앞서 `NET_RX_SOFTIRQ` enum값이 `net_rx_action()`함수와 매핑되는 함수이기도 하다.

```c
	/*
	* Initialise the packet receive queues.
	*/
	  
	for_each_possible_cpu(i) {
		struct work_struct *flush = per_cpu_ptr(&flush_works, i);
		struct softnet_data *sd = &per_cpu(softnet_data, i);
		  
		INIT_WORK(flush, flush_backlog);
		  
		skb_queue_head_init(&sd->input_pkt_queue);
		skb_queue_head_init(&sd->process_queue);
#ifdef CONFIG_XFRM_OFFLOAD
		skb_queue_head_init(&sd->xfrm_backlog);
#endif
		INIT_LIST_HEAD(&sd->poll_list);
		sd->output_queue_tailp = &sd->output_queue;
#ifdef CONFIG_RPS
		INIT_CSD(&sd->csd, rps_trigger_softirq, sd);
		sd->cpu = i;
#endif
		INIT_CSD(&sd->defer_csd, trigger_rx_softirq, sd);
		spin_lock_init(&sd->defer_lock);
		  
		init_gro_hash(&sd->backlog);
		sd->backlog.poll = process_backlog;
		sd->backlog.weight = weight_p;
		  
		if (net_page_pool_create(i))
			goto out;
	}
	  
dev_boot_phase = 0;
```

>위는 `net_dev_init()`함수의 중간부분이다. 여기서 `softnet_data`가 초기화되는 것을 알 수 있다. `softnet_data`의 `input_pkt_queue`, `process_queue`를 `skb_queue_head`타입의 리스트로써 `prev`, `next`를 우선 자신을 가르키도록 초기화해준다. 또한, `poll_list`를 `list_head`타입으로써 초기화 하게 된다.
>
>그리고 RPS가 설정되어 있다면, `rps_trigger_softirq`함수를 `csd`의 `func`멤버에 매핑하여, 만약 다른 CPU를 IPI를 통해 인터럽트를 일으켰을 때 실행할 hardware IRQ에 사용될 함수를 설정하게 된다.
>
>마지막으로 `napi`를 초기화하게 되는데, 여기서 이름은 `backlog`이다. `poll`함수를 `process_backlog`함수로 매핑하게 되고, `weight`은 한 번에 폴링 할 개수가 된다.
>
>>`process_backlog`함수를 간단하게 살펴보면, 우선 `net_rx_action()`이 끝나는 것을 기다릴 필요 없이 해당 CPU에 `ipi_list`, 즉 ipi를 할 리스트가 존재한다면, `net_rps_action_and_irq_enale()`함수를 바로 실행시키게 되고, 이후 `process_queue`에 담겨있는 `skb`를 하나씩 꺼내서 `__netif_receive_skb()`함수를 통해 네트워크 스택으로 올려주게 된다. 여기서 특징은 복잡한 RPS, GRO 등의 과정을 전혀 거치지 않는다는 점이다.
>>물론 첫 번째 실행에서는 `process_queue`가 비어있을 것이다. `enqueue_to_backlog`에서는 `input_pkt_queue`에 삽입하기 때문이다.
>>위의 상위 스택으로 넘기는 과정 이후에 `input_pkt_queue`가 비어있는지 검사하게 되는데, 비워질 때 까지 `skb_queue_splice_tail_init()`함수를 통해 해당 큐를 `process_queue`에 옮기는 과정이 반복된다. 따라서 `input_pkt_queue`가 처리되게 된다. 
>
>

