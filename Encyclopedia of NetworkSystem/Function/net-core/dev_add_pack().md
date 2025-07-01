---
Location: /net/core/dev.c
Return: void
Parameter: packet_type
---
```c
/**
* dev_add_pack - add packet handler
* @pt: packet type declaration
*
* Add a protocol handler to the networking stack. The passed &packet_type
* is linked into kernel lists and may not be freed until it has been
* removed from the kernel lists.
*
* This call does not sleep therefore it can not
* guarantee all CPU's that are in middle of receiving packets
* will see the new packet type (until the next received packet).
*/
  
void dev_add_pack(struct packet_type *pt)
{
	struct list_head *head = ptype_head(pt);
	  
	spin_lock(&ptype_lock);
	list_add_rcu(&pt->list, head);
	spin_unlock(&ptype_lock);
}
EXPORT_SYMBOL(dev_add_pack);
```

> 역할이 패킷 핸들러가 맞았다. 네트워크 스택에다가 프로토콜 별로 적용할 수 있는 패킷 핸들럴를 추가하는 역할을 하게 된다.

>`ptype_head`함수가 어떤 것인지는 `__netif_receive_skb_core()`함수 분석 노트에서 같이 다루었다.
>[[`__netif_receive_skb_core() 함수에 대한 로직 분석과 고찰 및 의의]]
>따라서 패킷 핸들러의 성격에 따라 4가지의 저장소로 가게 되는 것이다. 해당 list_head에 이 패킷핸들러를 추가하게 된다.