---
Parameter:
  - napi_struct
Return: void
Location: /include/net/gro.h
---

```c title=gro_normal_list()
/* Pass the currently batched GRO_NORMAL SKBs up to the stack. */
static inline void gro_normal_list(struct napi_struct *napi)
{
	if (!napi->rx_count)
		return;
	netif_receive_skb_list_internal(&napi->rx_list); // [[Encyclopedia of NetworkSystem/Function/net-core/netif_receive_skb_list_internal().md|netif_receive_skb_list_internal()]]
	INIT_LIST_HEAD(&napi->rx_list);
	napi->rx_count = 0;
}
```

[[Encyclopedia of NetworkSystem/Function/net-core/netif_receive_skb_list_internal().md|netif_receive_skb_list_internal()]]

> `napi->rx_list`를 통째로 parameter로 넘기면서, `napi->rx_list`와 `napi->rx_count`를 초기화 하고 있다. 따라서, `netif_receive_skb_list_internal`에서 해당 리스트에 있는 skb들은 완전히 스택으로 넘어가서 처리되는 것으로 보인다.