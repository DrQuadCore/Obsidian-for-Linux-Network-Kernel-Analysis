---
Parameter:
  - sk_buff
Return: int
Location: /net/ipv4/ip_input.c
---
```c title=ip_local_deliver코드
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	* Reassemble IP fragments.
	*/
	struct net *net = dev_net(skb->dev);
	  
	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}
	  
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
				net, NULL, skb, skb->dev, NULL,
				ip_local_deliver_finish);
}
```

>L4에 패킷을 전달하는 함수이다. 만약 fragment 되어있는 패킷이라면 이를 재조립하는 `ip_defrag()`호출하고, 0을 반환한다. 이 때, frage 되어있는지 여부를 확인하는 `ip_is_fragment()`함수의 경우 간단하게 비트 비교를 하는 방식으로 구현되어 있다.
>
>여기서 두 번째 `NF_HOOK`을 만날 수 있다. 여기서 보면, `NF_INET_LOCAL_IN`이라는 enum값과 함께 호출되는 것을 볼 수 있다. 앞에서는 pre routing이였지만, 여기서는 실질적으로 이 기기의 local로 들어가는 부분이다. 이후, `ip_local_deliver_finish()`함수를 호출하게 된다.

[[ip_defrag()]]
[[ip_local_deliver_finish()]]
