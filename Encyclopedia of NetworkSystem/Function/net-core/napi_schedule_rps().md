---
Parameter:
  - softnet_data
Return: void
Location: /net/core/dev.c
---
```c
/*
 * After we queued a packet into sd->input_pkt_queue,
 * we need to make sure this queue is serviced soon.
 *
 * - If this is another cpu queue, link it to our rps_ipi_list,
 *   and make sure we will process rps_ipi_list from net_rx_action().
 *
 * - If this is our own queue, NAPI schedule our backlog.
 *   Note that this also raises NET_RX_SOFTIRQ.
 */
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

[[황재훈/Research Intern/081324/net_rx_action()|net_rx_action()]]

input_pkt_queue에 pkt을 넣은 후에, 이 queue가 실행되도록 설정하는 함수이다.
다른 cpu를 위한 queue일 경우, rps_ipi_list (inter process interrupt list)에 넣는다.
올바른 cpu 인 경우에는, napi schedule을 실행한다.


```c
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