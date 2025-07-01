---
Parameter:
  - sk_buff
Return: int
Location: /net/core/dev.c
---
```c
int netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	trace_netif_receive_skb_entry(skb);

	ret = netif_receive_skb_internal(skb);
	trace_netif_receive_skb_exit(ret);

	return ret;
}
EXPORT_SYMBOL(netif_receive_skb);
```

네트워크에서 가져온 rx buffer를 처리한다
buffer가 congestion control 이나 다른 layer에 의해 드랍될 수 있다.
softirq context 에서만 콜 될 수 있다. interrupt이 허용된다.

trace_netif_receive_skb_entry, exit은 디버깅을 위한 코드이다?


NET_RX_SUCCESS : no congestion
NET_RX_DROP : packet dropped

[[netif_receive_skb_internal()]]
