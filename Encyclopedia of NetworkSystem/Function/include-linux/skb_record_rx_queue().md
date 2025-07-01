---
Parameter:
  - sk_buff
  - u16
Return: void
Location: /include/linux/skbuff.h
---

```c title=skb_record_rx_queue()
static inline void skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{
	skb->queue_mapping = rx_queue + 1;
}
```

> skb에 해당하는 rx_queue를 기록하는 간단한 인라인 함수이다.