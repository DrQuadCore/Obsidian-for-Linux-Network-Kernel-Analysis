# napi_struct와 poll_list
## 목적
- napi_struct가 정확히 무엇을 위한 구조체인지 파악하고자 합니다.
	- 흔히 말하는 napi의 버퍼가 커널 코드에서 어떻게 나타나는지 파악하고자 합니다.
- ice_q_vector, softnet_data, napi_struct, poll_list 간의 관계를 파악하고자 합니다.

## 결론
- ice_q_vector는 tx/rx queue pair 당 1개씩 존재합니다.
	- tx/rx queue가 ***보통 코어 당 1개씩*** 존재하므로 ice_q_vector도 코어 당 1개씩 존재하게 됩니다.
	- 즉, ***일반적으로*** napi_struct도 rx queue 당 1개씩 존재하게 됩니다.
- softnet_data는 ***코어 당 1개씩 존재***합니다.
---
- 일반적으로 생각하는 패킷 하나는 sk_buff 즉, skb입니다.
- 일반적으로 생각하는 ***napi의 ring buffer는 q_vector의 ice_ring 멤버***입니다.
---
- napi_struct는 ***각 상황을 나타내는 구조체***입니다.
	- 예)
		- X NIC -> A코어로 가는 상황 
		- X NIC -> B코어로 가는 상황
		- Y NIC -> A코어로 가는 상황
		- B코어 -> A코어로 가는 상황
- 같은 softirq context에서 처리되어야할 napi_struct들이 서로 list로 연결됩니다.
	- NIC으로부터 패킷이 들어온 경우 + 백로그로 skb가 넘어온 경우
	- 이러한 경우, napi_struct가 여러 개가 되어 list로 연결됩니다.
## 구조체
```c
struct list_head {
	struct list_head *next, *pref;
};
```
- list_head 구조체입니다.
- list_head 구조체는 두 개의 포인터를 멤버로 가집니다.


```c
struct softnet_data {
	struct list_head poll_list;
	struct sk_buff_head process_queue;
	
	...
	struct sk_buff_head input_pkt_queue;
	...
```
- softnet_data 구조체의 일부입니다.
- poll_list 멤버가 존재합니다.
	- 즉, list_head에 대한 포인터 멤버가 있는 것과 동일합니다.

```c
struct napi_struct {
	/* The poll_list must only be managed by the entity which
	 * changes the state of the NAPI_STATE_SCHED bit.  This means
	 * whoever atomically sets that bit can add this napi_struct
	 * to the per-CPU poll_list, and whoever clears that bit
	 * can remove from the list right before clearing the bit.
	 */
	struct list_head	poll_list;

```
- napi_struct 구조체의 일부입니다.
- poll_list 멤버가 존재합니다.

```c
/* struct that defines an interrupt vector */
struct ice_q_vector {
	struct ice_vsi *vsi;

	u16 v_idx;			/* index in the vsi->q_vector array. */
	u16 reg_idx;
	u8 num_ring_rx;			/* total number of Rx rings in vector */
	u8 num_ring_tx;			/* total number of Tx rings in vector */
	u8 wb_on_itr:1;			/* if true, WB on ITR is enabled */
	/* in usecs, need to use ice_intrl_to_usecs_reg() before writing this
	 * value to the device
	 */
	u8 intrl;

	struct napi_struct napi;

	struct ice_ring_container rx;
	struct ice_ring_container tx;
```
- ice_q_vector 구조체의 일부입니다.
- napi_struct를 멤버로 가지고 있습니다.
- ice_ring_container 구조체는 ice_ring의 정보를 가지고 있습니다. 즉, ring buffer의 정보를 가지있습니다.

```c
struct ice_ring_container {
	/* head of linked-list of rings */
	union {
		struct ice_rx_ring *rx_ring;
		struct ice_tx_ring *tx_ring; 
	};
	...
};

...

/* descriptor ring, associated with a VSI */
struct ice_rx_ring {
	/* CL1 - 1st cacheline starts here */
	void *desc;			/* Descriptor ring memory */
	struct device *dev;		/* Used for DMA mapping */
	struct net_device *netdev;	/* netdev ring maps to */
	struct ice_vsi *vsi;		/* Backreference to associated VSI */
	struct ice_q_vector *q_vector;	/* Backreference to associated vector */
	
	...

	union {
		struct ice_rx_buf *rx_buf;
		struct xdp_buff **xdp_buf;
	};

	...
	
	struct ice_rx_ring *next;	/* pointer to next ring in q_vector */

	...
} ____cacheline_internodealigned_in_smp;

...

struct ice_rx_buf {
	dma_addr_t dma;
	struct page *page;
	unsigned int page_offset;
	unsigned int pgcnt;
	unsigned int pagecnt_bias;
};
```
- ice_rx_ring 구조체의 desc 멤버는 napi 디스크립터에 대한 정보를 담고 있습니다.
- desc를 기반으로 rx_buf의 값을 채웁니다.
- desc와 rx_buf 둘 다 배열입니다.
	- 타입이 포인터인 것을 알 수 있습니다.


## 상황 1 - NIC으로부터 인터럽트 발생
- NIC에 의해 인터럽트가 발생 시, ice_q_vector에 있는 napi_struct의 poll_list가 지금 실행 중인 코어의 softnet_data의 poll_list로 옮겨갑니다.
	- ice_msix_clean_rings(), napi_schedule() 함수 등에 의해서 옮겨갑니다.

```c
static irqreturn_t ice_msix_clean_rings(int __always_unused irq, void *data)
{
	struct ice_q_vector *q_vector = (struct ice_q_vector *)data;
	...
	napi_schedule(&q_vector->napi);
	...
}
```
- ice_ msix_clean_rings()의 코드 일부분입니다.
- q_vector로부터 napi_struct를 가져와 napi_schedule()로 넘깁니다.

```c
static inline bool napi_schedule(struct napi_struct *n)
{
	if (napi_schedule_prep(n)) {
		__napi_schedule(n);
		...
}

...

void __napi_schedule(struct napi_struct *n)
{
	...
	____napi_schedule(this_cpu_ptr(&softnet_data), n);
	...
}

...

static inline void ____napi_schedule(struct softnet_data *sd,
				     struct napi_struct *napi)
{
	...
	list_add_tail(&napi->poll_list, &sd->poll_list);
	...
	if (!sd->in_net_rx_action)
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
}

...

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}
```
- call flow에 따른 각 함수들의 일부분입니다.
- q_vector의 napi_struct 매개변수로 넘겨지면서, 최종적으로 현재 인터럽트를 처리하고 있는 코어의 softnet_data의 poll_list로 napi_struct의 poll_list가 넘어가는 것을 볼 수 있습니다. 

## 상황 2 - 백로그로 skb 넘기기
- RPS를 통해 skb를 특정 코어의 백로그로 넘기고자 합니다다.

```c
static int enqueue_to_backlog(struct sk_buff *skb, int cpu,
			      unsigned int *qtail)
{
	...
	sd = &per_cpu(softnet_data, cpu);
	
	...
		if (qlen) {
			...
enqueue:
			__skb_queue_tail(&sd->input_pkt_queue, skb);
			...
		}
		
		...
		if (!__test_and_set_bit(NAPI_STATE_SCHED, &sd->backlog.state))
			napi_schedule_rps(sd);
	...
}
```
- enqueue_to_backlog() 함수의 일부분입니다.
- 넘길 cpu의 sd를 찾아서 skb를 넘깁니다.
- 이후, sd를 napi_schedule_rps() 함수로 넘깁니다.

```c
static void napi_schedule_rps(struct softnet_data *sd)
{
	struct softnet_data *mysd = this_cpu_ptr(&softnet_data);

#ifdef CONFIG_RPS
	if (sd != mysd) {
		sd->rps_ipi_next = mysd->rps_ipi_list;
		mysd->rps_ipi_list = sd;

		/* If not called from net_rx_action() or napi_threaded_poll()
		 * we have to raise NET_RX_SOFTIRQ.
		 */
		if (!mysd->in_net_rx_action && !mysd->in_napi_threaded_poll)
			__raise_softirq_irqoff(NET_RX_SOFTIRQ);
		return;
	}
#endif /* CONFIG_RPS */
	__napi_schedule_irqoff(&mysd->backlog);
}
```
- sd가 현재 코어의 sd인지 확인합니다.
	- sd가 현재 코어의 sd라면 \_\_napi_schedule_irqoff()를 호출합니다.
	- sd가 현재 코어의 sd가 아니라면, 즉, 다른 cpu로 보내야한다면
		- softirq를 요청합니다.
	- 즉, 2가지의 경우로 분기합니다.

### 상황 2.1 - sd가 현재 코어의 sd인 경우
```c
void __napi_schedule_irqoff(struct napi_struct *n)
{
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
		____napi_schedule(this_cpu_ptr(&softnet_data, n);
	else
		__napi_schedule(n);
}

...

static inline void ____napi_schedule(struct softnet_data *sd,
				     struct napi_struct *napi)
{
	...
	list_add_tail(&napi->poll_list, &sd->poll_list);
	...
	if (!sd->in_net_rx_action)
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
}

```
- 여기서의 napi_strucnt n은 backlog이므로, backlog를 sd의 poll_list에 붙입니다.
- 이후 softirq를 요청하여 처리합니다.

```c
static __latent_entropy void net_rx_action(struct softirq_action *h)
{
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);
	...
	int budget = READ_ONCE(net_hotdata.netdev_budget);
	LIST_HEAD(list);
	LIST_HEAD(repoll);

start:
	sd->in_net_rx_action = true;
	local_irq_disable();
	list_splice_init(&sd->poll_list, &list);
	local_irq_enable();

	for (;;) {
		struct napi_struct *n;	
		...

		n = list_first_entry(&list, struct napi_struct, poll_list);
		budget -= napi_poll(n, &repoll);

		...
}

...

static int napi_poll(struct napi_struct *n, struct list_head *repoll)
{
	bool do_repoll = false;
	void *have;
	int work;

	list_del_init(&n->poll_list);

	...

	work = __napi_poll(n, &do_repoll); // [[Encyclopedia of NetworkSystem/Function/net-core/__napi_poll().md|__napi_poll()]]

	...

	return work;
}

...

static int __napi_poll(struct napi_struct *n, bool *repoll)
{
	int work, weight;

	weight = n->weight;
	...
	work = 0;
	if (napi_is_scheduled(n)) {
		work = n->poll(n, weight);
		trace_napi_poll(n, work, weight);

		xdp_do_check_flushed(n);
	}

	if (unlikely(work > weight))
		netdev_err_once(n->dev, "NAPI poll function %pS returned %d, exceeding its budget of %d.\n",
				n->poll, work, weight);

	...
}

```
- softirq 처리에서 각 napi_struct에 맞는 n->poll이 호출됩니다.
- 해당 상황에서는 napi_struct가 backlog이므로 process_backlog()가 호출됩니다.

```c
static int process_backlog(struct napi_struct *napi, int quota)
{
	struct softnet_data *sd = container_of(napi, struct softnet_data, backlog);
	bool again = true;
	int work = 0;

	/* Check if we have pending ipi, its better to send them now,
	 * not waiting net_rx_action() end.
	 */
	if (sd_has_rps_ipi_waiting(sd)) {
		local_irq_disable();
		net_rps_action_and_irq_enable(sd);
	}

	napi->weight = READ_ONCE(net_hotdata.dev_rx_weight);
	while (again) {
		struct sk_buff *skb;

		local_lock_nested_bh(&softnet_data.process_queue_bh_lock);
		while ((skb = __skb_dequeue(&sd->process_queue))) {
			local_unlock_nested_bh(&softnet_data.process_queue_bh_lock);
			rcu_read_lock();
			__netif_receive_skb(skb);
			rcu_read_unlock();
			if (++work >= quota) {
				rps_input_queue_head_add(sd, work);
				return work;
			}

			local_lock_nested_bh(&softnet_data.process_queue_bh_lock);
		}
		local_unlock_nested_bh(&softnet_data.process_queue_bh_lock);

		backlog_lock_irq_disable(sd);
		if (skb_queue_empty(&sd->input_pkt_queue)) {
			/*
			 * Inline a custom version of __napi_complete().
			 * only current cpu owns and manipulates this napi,
			 * and NAPI_STATE_SCHED is the only possible flag set
			 * on backlog.
			 * We can use a plain write instead of clear_bit(),
			 * and we dont need an smp_mb() memory barrier.
			 */
			napi->state &= NAPIF_STATE_THREADED;
			again = false;
		} else {
			local_lock_nested_bh(&softnet_data.process_queue_bh_lock);
			skb_queue_splice_tail_init(&sd->input_pkt_queue,
						   &sd->process_queue);
			local_unlock_nested_bh(&softnet_data.process_queue_bh_lock);
		}
		backlog_unlock_irq_enable(sd);
	}

	if (work)
		rps_input_queue_head_add(sd, work);
	return work;
}
```
- container_of를 통해 backlog가 속한 sd를 가져옵니다.
- sd의 input_pkt_queue 멤버로부터 skb를 가져와 이후 네트워크 스택 처리를 진행합니다.
### 상황 2.2 - sd가 다른 코어의 sd인 경우
```c
static __latent_entropy void net_rx_action(struct softirq_action *h)
{
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);
	
	...

start:
	...
	list_splice_init(&sd->poll_list, &list);

	...

	for (;;) {
		struct napi_struct *n;

		...

		if (list_empty(&list)) {
			if (list_empty(&repoll)) {
				sd->in_net_rx_action = false;
				barrier();
				/* We need to check if ____napi_schedule()
				 * had refilled poll_list while
				 * sd->in_net_rx_action was true.
				 */
				if (!list_empty(&sd->poll_list))
					goto start;
				if (!sd_has_rps_ipi_waiting(sd))
					goto end;
			}
			break;
		}
		//napi_poll 동작 로직
		...
		
	}

	...
	
	net_rps_action_and_irq_enable(sd);
	...
}
```
- softirq를 처리하는 함수의 일부분입니다.
- 다른 코어의 sd인 경우, sd의 poll_list에 넣지 않았으니, list가 비워져있습니다.
- 따라서 napi_poll을 처리하지 않고 break를 통해 반복문을 빠져 나오게 됩니다.
- 이후, net_rps_action_and_irq_enable() 함수를 호출하여 다른 코어로 ipi를 보내고 다른 코어에서 처리됩니다.

```c
static void rps_trigger_softirq(void *data)
{
	struct softnet_data *sd = data;
	____napi_schedule(sd, &sd->backlog);
	...
}
```
- ipi를 받은 코어에서 해당 함수가 호출되고 sd의 backlog를 스케쥴하게 됩니다.
- 이후 과정은 상황 2.1과 동일합니다.