---
Parameter:
  - sk_buff
  - net
Return: sk_buff
Location: /net/ipv4/ip_input.c
---
```c title=ip_receive_core코드
/*
* Main IP Receive routine.
*/
static struct sk_buff *ip_rcv_core(struct sk_buff *skb, struct net *net)
{
	const struct iphdr *iph;
	int drop_reason;
	u32 len;
	  
	/* When the interface is in promisc. mode, drop all the crap
	* that it receives, do not try to analyse it.
	*/
	if (skb->pkt_type == PACKET_OTHERHOST) {
		dev_core_stats_rx_otherhost_dropped_inc(skb->dev);
		drop_reason = SKB_DROP_REASON_OTHERHOST;
		goto drop;
	}
	  
	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);
	  
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}
	  
	drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;
	  
	iph = ip_hdr(skb);
	  
	/*
	* RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	*
	* Is the datagram acceptable?
	*
	* 1. Length at least the size of an ip header
	* 2. Version of 4
	* 3. Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	* 4. Doesn't have a bogus length
	*/
	  
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;
	  
	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	__IP_ADD_STATS(net,
				IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
				max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));
	  
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;
	  
	iph = ip_hdr(skb);
	  
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;
	  
	len = iph_totlen(skb, iph);
	if (skb->len < len) {
		drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;
	  
	/* Our transport medium may have padded the buffer out. Now we know it
	* is IP we can trim to the true length of the frame.
	* Note this now means skb->len holds ntohs(iph->tot_len).
	*/
	if (pskb_trim_rcsum(skb, len)) {
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}
	  
	iph = ip_hdr(skb);
	skb->transport_header = skb->network_header + iph->ihl*4;
	  
	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;
	  
	/* Must drop socket now because of tproxy. */
	if (!skb_sk_is_prefetched(skb))
		skb_orphan(skb);
	  
	return skb;
	  
csum_error:
	drop_reason = SKB_DROP_REASON_IP_CSUM;
	__IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
	drop_reason = SKB_DROP_REASON_IP_INHDR;
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb_reason(skb, drop_reason);
out:
	return NULL;
}
```

>만약 패킷이 다른 호스트가 목적지라면 패킷은 드랍되게 된다.
>여기서는 `skb->pkt_type`을 확인하게 되는데, define을 통해 매핑된 숫자가 해당 패킷의 타입으로 설정되어 있다.

```c title=packet_type_mapping
/* Packet types */

  

#define PACKET_HOST 0 /* To us */

#define PACKET_BROADCAST 1 /* To all */

#define PACKET_MULTICAST 2 /* To group */

#define PACKET_OTHERHOST 3 /* To someone else */

#define PACKET_OUTGOING 4 /* Outgoing of any type */

#define PACKET_LOOPBACK 5 /* MC/BRD frame looped back */

#define PACKET_USER 6 /* To user space */

#define PACKET_KERNEL 7 /* To kernel space */

/* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */

#define PACKET_FASTROUTE 6 /* Fastrouted frame */
```

>이후 패킷이 공유 중인 상태인지 확인하고, ip 헤더를 가져오게 된다.
>가져온 아이피 헤더를 가지고 헤더의 길이, ip 버전, checksum, 전체 길이 등을 비교하여 오류가 있을 경우 그 에러에 해당하는 라벨로 `goto`가 이루어진다. 다만, 명시된 패킷의 길이가 수신한 것보다 짧다면 그 때는 패킷을 드랍하게 된다. 에러 라벨로 가보면 해당하는 `drop_reason`을 세팅하고 `skb free`이후에 `NULL`값을 리턴하고 있음을 볼 수 있다.
>
>또한, `skb->transport_header` 포인터는 여기서 설정하게 되는데, `skb->network_header`에서 ip header의 길이만큼 더해줌으로써 계산할 수 있다.

1. 패킷 타입 확인: PACKET_OTHERHOST 타입의 패킷을 걸러낸다. 이 패킷은 다른 호스트를 위한 것으로, 현재 호스트에서 처리되지 않으므로 드롭된다.
``` c
if (skb->pkt_type == PACKET_OTHERHOST) {
    dev_core_stats_rx_otherhost_dropped_inc(skb->dev);
    drop_reason = SKB_DROP_REASON_OTHERHOST;
    goto drop;
}
```

2. 통계 업데이트: 네트워크 통계를 업데이트하여 수신된 패킷의 길이를 기록한다. 
``` c
__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);
```

3. 공유 버퍼 확인: 패킷이 공유된 버퍼인지를 확인하고, 필요 시 새로운 버퍼로 복사한다. 복사에 실패하면 패킷을 드롭한다.
``` c
skb = skb_share_check(skb, GFP_ATOMIC);
if (!skb) {
    __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
    goto out;
}
```

4. IP 헤더 길이 확인: IP 헤더의 최소 길이를 확보할 수 있는지 확인한다. 확보하지 못하면 패킷을 드롭한다. 
``` c
drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
if (!pskb_may_pull(skb, sizeof(struct iphdr)))
    goto inhdr_error;
```

5. IP 헤더 참조: IP 헤더의 시작을 가리키는 포인터를 가져온다. 
``` c
iph = ip_hdr(skb);
```

6. IP 버전과 헤더 길이 확인: IP 헤더 길이와 버전이 유효한지 확인한다. IP 버전이 4가 아니거나, 헤더 길이가 5보다 작으면 패킷을 드롭한다. 
``` c
if (iph->ihl < 5 || iph->version != 4)
    goto inhdr_error;
```

7. 전체 IP 헤더 가져오기: 전체 IP 헤더를 가져올 수 있는지 확인한다. 실패하면 패킷을 드롭한다. 
``` c
if (!pskb_may_pull(skb, iph->ihl*4))
    goto inhdr_error;
```

8. 체크섬 검사: IP 헤더의 체크섬이 유효한지 확인한다. 체크섬이 올바르지 않으면 패킷을 드롭한다. 
``` c
iph = ip_hdr(skb);
if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
    goto csum_error;
```

9. 패킷 길이 확인: 패킷의 길이가 IP 헤더의 길이와 일치하는지 확인한다. 일치하지 않으면 패킷을 드롭한다. 
``` c
len = iph_totlen(skb, iph);
if (skb->len < len) {
    drop_reason = SKB_DROP_REASON_PKT_TOO_SMALL;
    __IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
    goto drop;
} else if (len < (iph->ihl*4))
    goto inhdr_error;
```

10. 패킷 길이 조정: 패킷이 더 길다면 IP 헤더의 총 길이에 맞춰 잘라낸다. 이 과정에서 문제가 발생하면 패킷을 드롭한다. 
``` c
if (pskb_trim_rcsum(skb, len)) {
    __IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
    goto drop;
}
```

 11. 전송 헤더 설정: IP 헤더 이후의 데이터가 전송 헤더이므로 그 시작점을 설정한다. 
``` c
iph = ip_hdr(skb);
skb->transport_header = skb->network_header + iph->ihl*4;
```

12. 소켓 제어 블록 초기화: 소켓 제어 블록을 초기화하여 잔여 데이터를 제거하고, 입력 인터페이스를 설정한다. 
``` C
memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
IPCB(skb)->iif = skb->skb_iif;
```

13. 소켓 고아 처리: 패킷이 소켓에 의해 미리 처리되지 않았으면 소켓 참조를 제거한다. 
``` C
if (!skb_sk_is_prefetched(skb))
    skb_orphan(skb);
```

14. 패킷 반환: 모든 검사를 통과한 패킷을 반환한다. 
``` C
return skb;
```

15. 오류 처리 및 패킷 드롭: 패킷이 검사에서 실패할 경우, 지전된 이유(drop_reason)로 패킷을 드롭하고, 관련 통계를 업데이트한다. 
``` C
csum_error:
drop_reason = SKB_DROP_REASON_IP_CSUM;
__IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
if (drop_reason == SKB_DROP_REASON_NOT_SPECIFIED)
drop_reason = SKB_DROP_REASON_IP_INHDR;
__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
kfree_skb_reason(skb, drop_reason);
out:
return NULL;
```