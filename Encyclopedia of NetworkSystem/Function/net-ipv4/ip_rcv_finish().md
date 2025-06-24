---
Parameter:
  - net
  - sock
  - sk_buff
Return: int
Location: /net/ipv4/ip_input.c
---
```c title=ip_rcv_finish코드
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	int ret;
	  
	/* if ingress device is enslaved to an L3 master device pass the
	* skb to its handler for processing
	*/
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;
	  
	ret = ip_rcv_finish_core(net, sk, skb, dev, NULL);
	if (ret != NET_RX_DROP)
		ret = dst_input(skb);
	return ret;
}
```
>l3mdev_ip_rcv() 함수로 skb를 가져온다. (layer 3 master device ip receive)
>skb가 존재하지 않을 경우 rx success를 리턴한다.
>
>실질적인 작업은 `ip_rcv_finish_core()`에서 이루어지는 것으로 보인다. 만약 드랍되는 패킷이 아니라면 `dst_input()`함수 또한 실행하게 되고 이후 결과를 return하게 된다.

[[ip_rcv_finish_core()]]
[[dst_input()]]
[[l3mdev_ip_rcv()]]
