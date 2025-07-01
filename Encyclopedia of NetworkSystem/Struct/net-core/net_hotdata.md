---
Location: /net/core/hotdata.c
---
```c title=net_hotdata
struct net_hotdata net_hotdata __cacheline_aligned = {

.offload_base = LIST_HEAD_INIT(net_hotdata.offload_base),

.ptype_all = LIST_HEAD_INIT(net_hotdata.ptype_all),

.gro_normal_batch = 8,

  

.netdev_budget = 300,

/* Must be at least 2 jiffes to guarantee 1 jiffy timeout */

.netdev_budget_usecs = 2 * USEC_PER_SEC / HZ,

  

.tstamp_prequeue = 1,

.max_backlog = 1000,

.dev_tx_weight = 64,

.dev_rx_weight = 64,

};

EXPORT_SYMBOL(net_hotdata);
```

>`net_hotdata`를 초기화하는 코드이다. 여기서 각종 설정 값들이 적용되게 된다. `gro_normal_batch`값을 따라가다보니 닿게 되었다. 여기서는 8로 셋팅되어 있다.