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
	skb = l3mdev_ip_rcv(skb); // [[l3mdev_ip_rcv()]]
	if (!skb)
		return NET_RX_SUCCESS;
	  
	ret = ip_rcv_finish_core(net, sk, skb, dev, NULL); // [[ip_rcv_finish_core()]]
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

---
netfilter의 hook chain을 모두 통과한 뒤 실제 라우팅 단계로 넘어가는 함수이다. 

ingress device, 즉 패킷이 커널 네트워크 스택에 들어올 때 처음 도착한 NIC이 L3 master에 소속돼 있거나(＝＝slave), master 자체일 경우, L3 master device 전용 핸들러에게 skb를 넘긴다. 이 핸들러에서 skb를 다 처리했을 경우 할 일이 없으므로 NET_RX_SUCCESS로 빠져나온다.

ingress device가 L3 master 혹은 L3 slave가 아닌 경우 dst entry를 얻기 위해 `ip_rcv_finish_core(net, sk, skb, dev, NULL)` 함수를 호출한다.

return 값 확인 후 `dst_input()`을 부른다. 

