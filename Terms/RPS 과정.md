
## RPS 과정

[[obsidian://open?vault=Obsidian-for-Linux-Network-Kernel-Analysis&file=Encyclopedia%20of%20NetworkSystem%2FStruct%2Finclude-linux%2Fsoftnet_data|softnet_data 구조체]]

- softnet_data 구조체 안에서 backlog는 `struct napi_struct backlog;` 로 정의되어 있다. 
  backlog는 자신의 CPU 코어에서 처리할 skb를 담고 있는 napi_struct 이다. softnet_data가 CPU 코어 당 1개씩 할당되어 있는 만큼 backlog 도 코어 당 고유의 napi struct를 갖고 있다.

1. `enqueue_to_backlog()` 에서 타겟 CPU 코어의 backlog 큐에 skb 를 넣는다. 이는 
   [[obsidian://open?vault=Obsidian-for-Linux-Network-Kernel-Analysis&file=Encyclopedia%20of%20NetworkSystem%2FFunction%2Fnet-core%2Fenqueue_to_backlog()|enqueue_to_backlog()]] 에서 코드를 확인할 수 있다.
   주의해야 할 점은 현재 폴링중인 napi_struct 자체를 타겟 CPU 코어에서 다루지 않는다는 점이다.
   만약, 그 cpu의 input_pck_queue가 비어있는 상황이면, napi_schedule_rps() 함수를 호출한다.

2. `napi_schedule_rps()` 에서 타겟 CPU 코어의 softnet_data를 현재 CPU 코어에 할당되어 있는 softnet_data->rps_ipi_list에 추가하게 된다. 
  이에 대한 세부 코드 및 설명은 [[obsidian://open?vault=Obsidian-for-Linux-Network-Kernel-Analysis&file=Encyclopedia%20of%20NetworkSystem%2FFunction%2Fnet-core%2Fnapi_schedule_rps()|napi_schedule_rps()]] 함수에 소개되어 있다.

3. 이에 대한 처리는 `net_rx_action()` 마지막 부분의 `net_rps_action_and_irq_enable()` 함수에서 시작된다. 
   [[obsidian://open?vault=Obsidian-for-Linux-Network-Kernel-Analysis&file=Encyclopedia%20of%20NetworkSystem%2FFunction%2Fnet-core%2Fnet_rps_action_and_irq_enable()|net_rps_action_and_irq_enable()]]
   현재 softnet_data의 rps_ipi_list를 확인해서, 해당 CPU 코어에 IPI(Inter Processor Interrupt)를 보내 된다. 이는 `net_rps_send_ipi()` 함수를 호출하면서 이루어진다. 
   
```
static void net_rps_send_ipi(struct softnet_data *remsd)
{
#ifdef CONFIG_RPS
	while (remsd) {
		struct softnet_data *next = remsd->rps_ipi_next;

		if (cpu_online(remsd->cpu))
			smp_call_function_single_async(remsd->cpu, &remsd->csd);
		remsd = next;
	}
#endif
}
```

  4. 인터럽트를 받은 타겟 CPU는 `rps_trigger_softirq()` 함수를 호출해 타겟 CPU 코어의 backlog를 스케줄링한다. 이 과정에서 다른 CPU 코어에서 스케줄링 하는 backlog는 원래 폴링 중이었던 napi_struct와는 다른 인스턴스라는 것을 알고 있어야 한다. 
  
     즉, RPS를 수행하더라도 다른 napi_struct를 스케줄링하는 것이므로 같은 napi_struct를 다른 코어에서 스케줄링 하는 경우는 없는 것이다.
  ```
/* Called from hardirq (IPI) context */
static void rps_trigger_softirq(void *data)
{
	struct softnet_data *sd = data;

	____napi_schedule(sd, &sd->backlog);
	sd->received_rps++;
}
```

5. 이렇게 backlog 또한 다른 napi_struct와 동일하게 스케줄링 되는 것을 확인할 수 있다. 이에 대한 처리는 napi_struct->poll() 을 호출할 때 다른 함수를 호출하면서 진행된다.
   `net_rx_action()` 함수 내부의 반복문에서 napi_struct->poll() 을 호출할 당시, 만약 현재 폴링 할 napi_struct가 backlog라면 `process_backlog()` 함수를 호출하고 다음 층에서 IP 헤더 처리 과정을 수행한다.

결과적으로 RPS의 IPI 를 통해서 napi_struct를 스케줄링 하는 것은 backlog이므로 다른 napi_struct를 스케줄링 하는 것이 된다.

   