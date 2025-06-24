---
Parameter:
  - void
Return: int
Location: /net/core/dev.c
---

```c title=net_dev_init()
/*
 *       This is called single threaded during boot, so no need
 *       to take the rtnl semaphore.
 */
static int __init net_dev_init(void)
{
	int i, rc = -ENOMEM;

	BUG_ON(!dev_boot_phase);

	net_dev_struct_check();

	if (dev_proc_init())
		goto out;

	if (netdev_kobject_init())
		goto out;

	for (i = 0; i < PTYPE_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ptype_base[i]);

	if (register_pernet_subsys(&netdev_net_ops))
		goto out;

	/*
	 *	Initialise the packet receive queues.
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

	/* The loopback device is special if any other network devices
	 * is present in a network namespace the loopback device must
	 * be present. Since we now dynamically allocate and free the
	 * loopback device ensure this invariant is maintained by
	 * keeping the loopback device as the first device on the
	 * list of network devices.  Ensuring the loopback devices
	 * is the first device that appears and the last network device
	 * that disappears.
	 */
	if (register_pernet_device(&loopback_net_ops))
		goto out;

	if (register_pernet_device(&default_device_ops))
		goto out;

	open_softirq(NET_TX_SOFTIRQ, net_tx_action);
	open_softirq(NET_RX_SOFTIRQ, net_rx_action);
	// net_tx_action과 net_rx_action을 softirq에 매핑
	
	rc = cpuhp_setup_state_nocalls(CPUHP_NET_DEV_DEAD, "net/dev:dead",
				       NULL, dev_cpu_dead);
	WARN_ON(rc < 0);
	rc = 0;
out:
	if (rc < 0) {
		for_each_possible_cpu(i) {
			struct page_pool *pp_ptr;

			pp_ptr = per_cpu(system_page_pool, i);
			if (!pp_ptr)
				continue;

			page_pool_destroy(pp_ptr);
			per_cpu(system_page_pool, i) = NULL;
		}
	}

	return rc;
}
```


``` c
// kernel/softirq.c
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
	softirq_vec[nr].action = action;
}

static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;

// include/linux/interrupt.h
struct softirq_action
{
	void	(*action)(struct softirq_action *);
};

```

**RTNL semaphore:**

리눅스 커널에서 라우팅 네트링크(RTNL) 인터페이스를 사용하는 동안 동기화 메커니즘으로 사용된다. 이는 여러 스레드나 프로세스가 네트워크 장치, 주소, 라우팅 테이블 등을 설정하거나 변경할 때 동시 접근을 조정하고, 데이터 일관성을 유지하기 위해 사용된다.

**주요 특징**

- **동기화**: 여러 스레드가 동시에 네트워크 설정을 변경하는 것을 방지.
- **보호**: 네트워크 설정을 변경하는 동안 데이터 일관성을 유지.
- **락(lock) 메커니즘**: 세마포어를 사용하여 다른 프로세스가 네트워크 설정에 접근하는 것을 제어.