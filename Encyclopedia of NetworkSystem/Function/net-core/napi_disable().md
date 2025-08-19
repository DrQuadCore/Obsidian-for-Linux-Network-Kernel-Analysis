---
Parameter:
  - napi_struct
Return: void
Location: /net/core/dev.c
---
```c napi_disable()
/**
 *	napi_disable - prevent NAPI from scheduling
 *	@n: NAPI context
 *
 * Stop NAPI from being scheduled on this context.
 * Waits till any outstanding processing completes.
 */

void napi_disable(struct napi_struct *n)
{
	unsigned long val, new;

	might_sleep();
	set_bit(NAPI_STATE_DISABLE, &n->state); // 여기서 DISABLE flag 켬

	val = READ_ONCE(n->state);
	do {  
		while (val & (NAPIF_STATE_SCHED | NAPIF_STATE_NPSVC)) {
			usleep_range(20, 200);
			val = READ_ONCE(n->state);
		}

		new = val | NAPIF_STATE_SCHED | NAPIF_STATE_NPSVC; 
		new &= ~(NAPIF_STATE_THREADED | NAPIF_STATE_PREFER_BUSY_POLL);
	} while (!try_cmpxchg(&n->state, &val, new)); // n->state update

	hrtimer_cancel(&n->timer);

	clear_bit(NAPI_STATE_DISABLE, &n->state); // DISALBE flag 끔
}
EXPORT_SYMBOL(napi_disable);
```

함수가 호출될 경우, `NAPI_STATE_DISABLE` flag를 켜고, `NAPIF_STATE_SCHED`, `NAPIF_STATE_NPSVC` flag 중 하나라도 켜져 있을 경우 계속 usleep을 호출한다. 
두 flag 중 하나라도 꺼졌을 경우에는, n->state 값을 update 한 뒤, `NAPI_STATE_DISABLE` flag를 다시 끈다. 

진행 중인 napi polling을 막는 함수가 아니라, napi의 ownership이 해제될 때까지 (= 현재 진행 중인 polling이 끝날 때까지) 기다리면서 동시에 `NAPI_STATE_DISABLE` flag로 또 다른 스케줄링 요청을 막는 함수이다. 
(napi_enable() and napi_disable() manage the disabled state. A disabled NAPI can’t be scheduled and its poll method is guaranteed to not be invoked. napi_disable() *waits for ownership* of the NAPI instance to be released. [NAPI — The Linux Kernel documentation](https://docs.kernel.org/networking/napi.html))

진행 중인 polling이 끝나면, NAPIF_STATE_SCHED flag를 켜서 이후에 NAPI_STATE_DISABLE flag를 꺼도 더 이상 스케줄 되지 않는다. 

>Referenced in
+ 드라이버에서 디바이스를 down 시킬 때나 삭제하는 과정 (qvector 정리하려면 napi부터 정리해야 함, softirq 레벨에서 여전히 napi->poll()이 돌고 있는데 지워버리면 qvector나 napi에 접근할 때 문제 생김)
	+ [gem_netif_stop](https://elixir.bootlin.com/linux/v6.9/C/ident/gem_netif_stop)
	+ [tc35815_close](https://elixir.bootlin.com/linux/v6.9/C/ident/tc35815_close)
	+ [spider_net_stop](https://elixir.bootlin.com/linux/v6.9/C/ident/spider_net_stop)
	
