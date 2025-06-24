---
Parameter:
  - net_device
  - napi_struct
  - int
Return: void
Location: /include/linux/netdevice.h
---

```c title=netif_napi_add()
/* Default NAPI poll() weight
 * Device drivers are strongly advised to not use bigger value
 */
 
#define NAPI_POLL_WEIGHT 64

/**
 * netif_napi_add() - initialize a NAPI context
 * @dev:  network device
 * @napi: NAPI context
 * @poll: polling function
 *
 * netif_napi_add() must be used to initialize a NAPI context prior to calling
 * *any* of the other NAPI-related functions.
 */
static inline void
netif_napi_add(struct net_device *dev, struct napi_struct *napi,
	       int (*poll)(struct napi_struct *, int)) // [[Encyclopedia of NetworkSystem/Struct/include-linux/napi_struct.md|napi_struct]]
{
	netif_napi_add_weight(dev, napi, poll, NAPI_POLL_WEIGHT);
	// [[Encyclopedia of NetworkSystem/Function/net-core/netif_napi_add_weight().md|netif_napi_add_weight()]]
}
```

[[Encyclopedia of NetworkSystem/Struct/include-linux/napi_struct.md|napi_struct]]
[[Encyclopedia of NetworkSystem/Function/net-core/netif_napi_add_weight().md|netif_napi_add_weight()]]

1. `netif_napi_add_weight(dev, napi, poll, NAPI_POLL_WEIGHT);` 가 안에 있다
    a. NAPI_POLL_WEIGHT == 64
2. `if (WARN_ON(test_and_set_bit(NAPI_STATE_LISTED, &napi->state)))`
    a. 이미 napi에 list가 있는 상태면 넘어간다
3. list의 초기값 설정, timer 초기값 설정
4. `init_gro_hash(napi);`
        
```c title=init_gro_hash()
        static void `init_gro_hash(`struct napi_struct *napi)
        {
        	int i;
        
        	for (i = 0; i < GRO_HASH_BUCKETS; i++) {
        		INIT_LIST_HEAD(&napi->gro_hash[i].list);
        		napi->gro_hash[i].count = 0;
        	}
        	napi->gro_bitmask = 0;
        }
```
    1. gro 준비
    2. gro_hash_bucket의 개수만큼 list를 초기화 해준다
    
1. napi 에 skb가 있는 이유
    a. napi_struct를 이어서 poll list를 만든다 ?
6. `napi_kthread_create(napi)`
        
```c title = napi_kthread_create()
        static int napi_kthread_create(struct napi_struct *n)
        {
        	int err = 0;
        
        	/* Create and wake up the kthread once to put it in
        	 * TASK_INTERRUPTIBLE mode to avoid the blocked task
        	 * warning and work with loadavg.
        	 */
        	n->thread = kthread_run(napi_threaded_poll, n, "napi/%s-%d",
        				n->dev->name, n->napi_id);
        	if (IS_ERR(n->thread)) {
        		err = PTR_ERR(n->thread);
        		pr_err("kthread_run failed with err %d\\n", err);
        		n->thread = NULL;
        	}
        
        	return err;
        }
```
    1. kthread를 만들면서 깨우고 interruptible mode로 설정한다
    2. blocked task warning을 피하고 loadavg를 사용하기 위해 한다 ????
       
7. `netif_napi_set_irq(napi, -1);`
   a. napi_struct에 있는 irq 변수를 -1로 설정한다
   b. enum 으로 설정되어 있을 것 같은데 -1로 설정한 것 보아 irq disable 한거랑 연관있을 듯?
   c. napi->irq = irq;

- Types of NAPI state
  ```c title = NAPIstate
    enum {
    	NAPI_STATE_SCHED,		/* Poll is scheduled */
    	NAPI_STATE_MISSED,		/* reschedule a napi */
    	NAPI_STATE_DISABLE,		/* Disable pending */
    	NAPI_STATE_NPSVC,		/* Netpoll - don't dequeue from poll_list */
    	NAPI_STATE_LISTED,		/* NAPI added to system lists */
    	NAPI_STATE_NO_BUSY_POLL,	/* Do not add in napi_hash, no busy polling */
    	NAPI_STATE_IN_BUSY_POLL,	/* sk_busy_loop() owns this NAPI */
    	NAPI_STATE_PREFER_BUSY_POLL,	/* prefer busy-polling over softirq processing*/
    	NAPI_STATE_THREADED,		/* The poll is performed inside its own thread*/
    	NAPI_STATE_SCHED_THREADED,	/* Napi is currently scheduled in threaded mode */
    };
    ```