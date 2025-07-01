---
Parameter:
  - net
  - sk_buff
  - int
Return: void
Location: /net/ipv4/ip_input.c
---
```c title=ip_protocol_deliver_rcu코드
void ip_protocol_deliver_rcu(struct net *net, struct sk_buff *skb, int protocol)
{
	const struct net_protocol *ipprot;
	int raw, ret;
	  
resubmit:
	raw = raw_local_deliver(skb, protocol);
	  
	ipprot = rcu_dereference(inet_protos[protocol]);
	if (ipprot) {
		if (!ipprot->no_policy) {
			if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
				kfree_skb_reason(skb,
						SKB_DROP_REASON_XFRM_POLICY);
				return;
			}
			nf_reset_ct(skb);
		}
		ret = INDIRECT_CALL_2(ipprot->handler, tcp_v4_rcv, udp_rcv,
					skb);
		if (ret < 0) {
			protocol = -ret;
			goto resubmit;
		}
		__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
	} else {
		if (!raw) {
			if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
			__IP_INC_STATS(net, IPSTATS_MIB_INUNKNOWNPROTOS);
			icmp_send(skb, ICMP_DEST_UNREACH,
				  ICMP_PROT_UNREACH, 0);
			}
			kfree_skb_reason(skb, SKB_DROP_REASON_IP_NOPROTO);
		} else {
			__IP_INC_STATS(net, IPSTATS_MIB_INDELIVERS);
			consume_skb(skb);
		}
	}
}
```

>`raw_local_deliver`함수를 통해 `raw`값을 받아온다. 여기서 `raw`는 해당 패킷이 RAW 소켓을 사용하는지 여부가 되게 된다. 그 다음으로 우선 유효한 프로토콜인지 확인하고, `no_policy`여부를 확인한다. 그후 `INDIRECT_CALL_2`함수를 통하여 해당 `ipprot`의 `handler`를 검사하여 `tcp_v4_rcv`혹은 `udp_rcv` 함수를 호출하게 된다. 만약 `ret`이 음수면 해당 `ret`값을 `protocol`값으로 다시 세팅하여 함수의 처음 부분으로 돌아가게 된다.
>만약 유효한 프로토콜이 아니라면 `raw`값이 `NULL`인경우 알지못하는 프로토콜로 간주하고 icmp를 보내게 되고, 아니라면 그냥 `skb`를 없애버린다.

[[raw_local_deliver()]] 
[[Encyclopedia of NetworkSystem/Function/net-ipv4/tcp_v4_rcv()]]
