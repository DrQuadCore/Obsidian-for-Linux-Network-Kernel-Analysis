---
Parameter:
  - softnet_data
Return: void
Location: /net/core/dev.c
---

```c title=net_rx_action()
static __latent_entropy void net_rx_action(struct softirq_action *h)
{
	struct softnet_data *sd = this_cpu_ptr(&softnet_data);
	unsigned long time_limit = jiffies +
		usecs_to_jiffies(READ_ONCE(net_hotdata.netdev_budget_usecs));
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

		skb_defer_free_flush(sd);

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

		n = list_first_entry(&list, struct napi_struct, poll_list);
		budget -= napi_poll(n, &repoll); //napi_poll이 이루어지는 부분
		// [[Encyclopedia of NetworkSystem/Function/net-core/napi_poll().md|napi_poll()]]

		/* If softirq window is exhausted then punt.
		 * Allow this to run for 2 jiffies since which will allow
		 * an average latency of 1.5/HZ.
		 */
		if (unlikely(budget <= 0 ||
			     time_after_eq(jiffies, time_limit))) {
			sd->time_squeeze++;
			break;
		}
	}

	local_irq_disable();

	list_splice_tail_init(&sd->poll_list, &list);
	list_splice_tail(&repoll, &list);
	list_splice(&list, &sd->poll_list);
	if (!list_empty(&sd->poll_list))
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
	else
		sd->in_net_rx_action = false;

	net_rps_action_and_irq_enable(sd); // [[Encyclopedia of NetworkSystem/Function/net-core/net_rps_action_and_irq_enable().md|net_rps_action_and_irq_enable()]]
end:;
}

struct netdev_adjacent {
	struct net_device *dev;
	netdevice_tracker dev_tracker;

	/* upper master flag, there can only be one master device per list */
	bool master;

	/* lookup ignore flag */
	bool ignore;

	/* counter for the number of times this device was added to us */
	u16 ref_nr;

	/* private field for the users */
	void *private;

	struct list_head list;
	struct rcu_head rcu;
};
```

[[Encyclopedia of NetworkSystem/Function/net-core/napi_poll().md|napi_poll()]]
[[Encyclopedia of NetworkSystem/Function/net-core/net_rps_action_and_irq_enable().md|net_rps_action_and_irq_enable()]]

> jiffies를 통해 time out을 구현하였고, softnet_data 구조체에서 poll_list를 가져왔다. 이후 이러한 리스트를 바탕으로 `napi_poll()` 함수를 호출하여 폴링을 시작하게 된다. `napi_poll` 함수는 네트워크 장치의 수신 큐에서 패킷을 처리하고, 이를 위해 할당된 budget을 감소시키는 역할을 한다.

--8.22 추가--
> `napi_poll`함수를 실행할 때, `napi_struct`를 `n`이라는 parameter로 넘기게 되는데, 따라서 for문을 돌 때마다 한 개씩  `napi_struct`가 처리되고 있음을 볼 수 있다. 
> 본 함수에서는 계속 `poll_list`의 첫 번째 entry만 가져오는 것 같지만 `napi_poll`함수 내부에서 해당 `napi_struct`를 `poll_list`에서 제거하므로, 전체 리스트를 적절하게 처리하고 있다고 볼 수 있다.
> 
> 즉 `budget`은 하나의 CPU에서 여러개의 `napi_struct`를 처리하는 전체 처리양의 예산인 것이다.


> 이때 `softnet_data`의 `poll_list`는 `____napi_schedule()`함수에서 해당 `napi_struct`가 추가 되는 것을 확인 할 수 있었다. 이렇게 여러 개의 `ice_q_vector`가 하나의 `softnet_data->poll_list`에 매핑되어, 그 CPU에서 softIRQ가 처리되게 되는 것이다.
> 
> 이후 `net_rx_action()` 함수가 실행 중인지 확인하여 실행 중이라면 그냥 `sd->poll_list`에 추가함으로써 해당 `net_rx_action()`에서 처리할 수 있도록하고, 만약 꺼져 있다면 새로이 켜게 되는 것이다.
> 
> 그렇다는 말은, `sd->backlog`도 `sd->poll_list`에 들어가게 된다는 의미이다. 그러나 `napi_struct`의 `poll`함수 포인터가 서로 다른 것을 가르키고 있을 것이다.
>> ring descriptor가 속해있는 `ice_q_vector`의 `napi_struct`인 경우 ->`ice_napi_poll`
>> `softnet_data`에 존재하는 `backlog`라는 이름의 napi_struct인 경우 ->`process_backlog`
>따라서 각기 다른 함수가 폴링을 하게 될 것이다.


**jiffies:**

리눅스 커널에서 시간을 측정하기 위해 사용되는 전역 변수이다. 시스템 부팅 시점부터 일정 주기마다 증가하는 카운터로, 타이머 인터럽트에 의해 업데이트된다. jiffies 값은 타임슬라이스 계산, 시간 제한 설정, 타이머 관리 등 다양한 시간 관련 작업에 사용된다.

**주요 특징**

- **단위**: jiffies는 시스템 타이머 인터럽트 주기와 관련되어 있다.
- **정확도**: HZ 매크로를 통해 1초에 몇 번의 jiffies 업데이트가 발생하는지 결정한다.
- **사용 예**: 시간 계산, 타임아웃 설정 등.
