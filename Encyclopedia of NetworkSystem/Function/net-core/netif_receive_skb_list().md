```c
/**
 *	netif_receive_skb_list - process many receive buffers from network
 *	@head: list of skbs to process.
 *
 *	Since return value of netif_receive_skb() is normally ignored, and
 *	wouldn't be meaningful for a list, this function returns void.
 *
 *	This function may only be called from softirq context and interrupts
 *	should be enabled.
 */
void netif_receive_skb_list(struct list_head *head)
{
	struct sk_buff *skb;

	if (list_empty(head))
		return;
	if (trace_netif_receive_skb_list_entry_enabled()) {
		list_for_each_entry(skb, head, list)
			trace_netif_receive_skb_list_entry(skb);
	}
	netif_receive_skb_list_internal(head);
	trace_netif_receive_skb_list_exit(0);
}
```

list 가 비어있는 경우 종료
`trace_netif_receive_skb_list_entry_enabled()` 는 trace point가 enable되어 있는지 리턴
`tracepoint()` 들 간에 race를 막는데 필요하다.
list에 있는 skb들을 순서대로  `trace_netif_receive_skb_list_entry(skb)` 돌린다.
tracepoint을 실행한다. tracepoint에는 probe function이 연결될 수 있다(연결되어 있으면 on  상테)
tracepoint이 실행될 때마다 probe 함수도 같이 실행된다. tracing performace accounting에 사용
https://www.kernel.org/doc/Documentation/trace/tracepoints.txt
https://blogs.oracle.com/linux/post/taming-tracepoints-in-the-linux-kernel
```c
DEFINE_EVENT(net_dev_rx_verbose_template, netif_receive_skb_list_entry,

	TP_PROTO(const struct sk_buff *skb),

	TP_ARGS(skb)
);
```
![[Pasted image 20240904104737.png]]
마지막으로 해당하는 list에 대해서 `netif_receive_skb_list_internal(head)` 실행한다.

[[netif_receive_skb_list_internal()]]
