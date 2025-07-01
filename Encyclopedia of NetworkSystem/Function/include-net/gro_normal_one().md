---
Parameter:
  - napi_struct
  - sk_buff
  - int
Return: void
Location: /include/net/gro.h
---

```c title=xdp_prepare_buff()
/* Queue one GRO_NORMAL SKB up for list processing. If batch size exceeded,
 * pass the whole batch up to the stack.
 */
static inline void gro_normal_one(struct napi_struct *napi, struct sk_buff *skb, int segs)
{
	list_add_tail(&skb->list, &napi->rx_list);
	napi->rx_count += segs;
	if (napi->rx_count >= READ_ONCE(net_hotdata.gro_normal_batch))
		gro_normal_list(napi); // [[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_list().md|gro_normal_list()]]
}
```

[[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_list().md|gro_normal_list()]]

> skb→list에다가 napi→rx_list를 추가하게 되며, 합친 segment 수만큼 rx_count를 증가하게 된다. 만약 gro_normal_batch보다 크기가 커진다면 이 전체를 스택에 넘기게 된다.

>해당 `skb`를 `napi->rx_list`에 새로이 올리게 된다. 여기서 `segs`는 `skb의 cb의 count`값인데, 이는 aggregated된 packet의 수 이다. 만약 이 rx_count의 종합이 `net_hotdata`에서 가져온 `gro_normal_batch`보다 크거나 같게 된다면 `gro_normal_list()`함수를 호출하게 된다. 그게 아니라면 그냥 넘어가게 된다. 그렇다면,[[Encyclopedia of NetworkSystem/Function/include-net/gro_normal_list().md|gro_normal_list()]]