---
Parameter:
  - skb_buff
Return: dst_entry
Location: /include/linux/skbuff.h
---
```c
/**
 * skb_dst - returns skb dst_entry
 * @skb: buffer
 *
 * Returns skb dst_entry, regardless of reference taken or not.
 */
static inline struct dst_entry *skb_dst(const struct sk_buff *skb)
{
	/* If refdst was not refcounted, check we still are in a
	 * rcu_read_lock section
	 */
	WARN_ON((skb->_skb_refdst & SKB_DST_NOREF) &&
		!rcu_read_lock_held() &&
		!rcu_read_lock_bh_held());
	return (struct dst_entry *)(skb->_skb_refdst & SKB_DST_PTRMASK);
}
```

------

이 skb가 어떤 경로로 나가야 하는지에 대한 라우팅 경로 정보를 담고 있는 dst_entry를 반환한다. 

refdst에 SKB_DST_NOREF가 켜졌다는 건, 이 dst_entry는 refcount 없이 RCU로만 보호되는 상태라는 것을 의미한다. 이런 경우 rcu_read_lock을 잡은 상태가 아니라면 read 하는 동안 dst_enty가 free 될 수 있기 때문에 경고 메시지를 출력한다.  

_ skb_refdst는 det_entry 정보 외에도 reference flag 정보도 담고 있다. 

```c
#define SKB_DST_NOREF	1UL
#define SKB_DST_PTRMASK	~(SKB_DST_NOREF)
```

따라서 SKB_DST_PTRMASK로 flag bit를 끄고 skb에 대한 dst_entry만을 반환한다. 

```c
struct dst_entry {
	struct net_device       *dev; // 이 패킷이 최종적으로 나갈(들어올) device
	struct  dst_ops	        *ops; 
	unsigned long		_metrics;
	unsigned long           expires;
#ifdef CONFIG_XFRM
	struct xfrm_state	*xfrm;
#else
	void			*__pad1;
#endif
	int			(*input)(struct sk_buff *);
	int			(*output)(struct net *net, struct sock *sk, struct sk_buff *skb); // skb를 실제로 전송하는 함수

	unsigned short		flags; 
#define DST_NOXFRM		0x0002 
#define DST_NOPOLICY		0x0004
#define DST_NOCOUNT		0x0008
#define DST_FAKE_RTABLE		0x0010
#define DST_XFRM_TUNNEL		0x0020
#define DST_XFRM_QUEUE		0x0040
#define DST_METADATA		0x0080

	/* A non-zero value of dst->obsolete forces by-hand validation
	 * of the route entry.  Positive values are set by the generic
	 * dst layer to indicate that the entry has been forcefully
	 * destroyed.
	 *
	 * Negative values are used by the implementation layer code to
	 * force invocation of the dst_ops->check() method.
	 */
	short			obsolete; // dst_entry의 상태를 나타냄
#define DST_OBSOLETE_NONE	0 // 정상 
#define DST_OBSOLETE_DEAD	2 // 이미 죽은 상태 (generic layer가 표시)
#define DST_OBSOLETE_FORCE_CHK	-1 // 다음에 쓸 때 check()를 호출해서 다시 확인 
#define DST_OBSOLETE_KILL	-2 // kill 하기로 예정된 상태 
...
...
...
};
```

+ generic layer: dst_entry를 관리하는 공통 계층
+ implementation layer: IPv4/IPv6 라우트 엔트리를 관리하는 계층