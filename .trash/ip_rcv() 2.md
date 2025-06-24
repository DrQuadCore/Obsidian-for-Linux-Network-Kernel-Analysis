---
Return:
  - int
Location: /net/ipv4/ip_input.c
Parameter:
  - sk_buff
  - net_device
  - packet_type
  - net_device_
---
*net_device parameter의 경우 두개인데, 중복으로 리스트에 추가 될 수 없어서 뒤에 under_bar를 달아 놓았다.*

```c title=ip_rcv코드
/*

* IP receive entry point

*/

int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,

struct net_device *orig_dev)

{

struct net *net = dev_net(dev);

  

skb = ip_rcv_core(skb, net);

if (skb == NULL)

return NET_RX_DROP;

  

return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,

net, NULL, skb, dev, NULL,

ip_rcv_finish);

}
```

>L3 protocol handler Layer이다.
>`ip_rcv_core()`함수를 호출하여 핵심 로직이 실행되고, 이에 대한 `return`으로 패킷의 drop 여부를 결정하게 된다.

[[ip_rcv_core()]]
[[ip_rcv_finish()]]
