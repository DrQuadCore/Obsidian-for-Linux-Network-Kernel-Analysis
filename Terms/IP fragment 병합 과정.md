## 구조체 요약

### sk_buff
네트워크 패킷. 실제 데이터는 없고 포인터로 각 헤더, 데이터 가리킴

### net_device
네트워크 인터페이스를 표현함. MAC 주소 등 가짐

### dst_entry
네트워크 패킷이 전달될 목적지의 네트워크 인터페이스, 사용할 함수 등 저장

### inet_frag_queue
fragment를 합치기 위해 모아놓은 큐

### ipq
아직 다 오지 않은 데이터그램의 큐.  inet_frag_queue, 최대로 fragment할 수 있는 크기 등 저장



---

### 1. `dst_input()`
 ipv4, ipv6에 따라 각각을 처리하는 함수를 실행
### 2. `ip_local_deliver()`
fragment이면 합치는 작업 수행(`ip_defrag()`)
이후 다음 작업으로 이동

### 3.1. `ip_defrag()`

### 3.2. `ip_local_deliver_finish()`
락을 잡고 상위 계층(L3, Trasfer)을 처리하는 함수 호출

### 4. `ip_protocol_deliver_rcu()`
프로토콜에 맞는 함수를 호출

### 5. `tcp_v4_rcv()`
IPv4 TCP 패킷을 검사, 소켓 상태에 따라 적절히 분기 처리, 3-way handshake, 일반 데이터 처리, TIME_WAIT 패킷 처리 등

---
### 6.1. `tcp_v4_do_rcv()`
TCP 소켓의 상태에 따라 패킷을 세분화하여 처리. ESTABLISHED 상태, LISTEN 상태, 그 외 상태에 따라 각 함수 호출, 오류 시 RST 패킷 전송

### 7.1. `tcp_rcv_established()`
빠른 경로와 느린 경로로 나누어서 패킷을 처리
ACK 패킷이면 `tcp_ack()`로 처리

### 8.1. `tcp_ack()`
수신된 ACK 패킷 검증 TCP 연결의 송신 상태 갱신, 혼잡 제어

### 9.1. `tcp_queue_rcv()`
기존의 가장 마지막 패킷과 합칠 수 있으면 합침(`tcp_try_coalesce()`)
소켓 수신 큐에 넣음(`__skb_queue_tail()`)
### 10.1. `tcp_data_queue()`
시퀀스가 맞으면 정상 처리(``tcp_queue_rcv()`)
시퀀스가 안 맞으면 rbtree에 넣어 관리(``tcp_data_queue_ofo()`)

---
### 6.2. `tcp_add_backlog()`
fragment가 있으면 합침(`skb_condense()`)
직전 backlog 패킷과 합칠 수 있으면 합침(`skb_try_coalesce()`)
이후 backlog에 넣음

## 7.2 `sk_add_backlog()`
backlog 연결 리스트에 넣음
이후 softirq 컨텍스트가 아니라 syscall 컨텍스트에서 backlog에 있는 패킷을 `sk_backlog_rcv()`로 처리(6.1~10.1 과정 수행)

---

## 1. ip_rcv_finish()
```c title=ip_rcv_finish코드
// net/ipv4/ip_input.c
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
>실질적인 작업은 `ip_rcv_finish_core()`에서 이루어지는 것으로 보인다. 
>만약 드랍되는 패킷이 아니라면 `dst_input()`함수 또한 실행하게 되고 이후 결과를 return하게 된다.

---
## 2. dst_input()
```c title=dst_input코드
// include/net/dst.h
INDIRECT_CALLABLE_DECLARE(int ip6_input(struct sk_buff *));
INDIRECT_CALLABLE_DECLARE(int ip_local_deliver(struct sk_buff *));
static inline int dst_input(struct sk_buff *skb)
{
	return INDIRECT_CALL_INET(skb_dst(skb)->input,
				  ip6_input, ip_local_deliver, skb);
}
```

>간단하게 `INDIRECT_CALL_INET` 함수 매크로를 호출하는 코드이다. 여기서도 ip 버전에 따라서 간접적으로 함수 호출이 이루어지게 된다. 여기서 중요하게 봐야할 것은 `dst_input`함수 그자체이다. `dst_output`함수도 존재하며, 똑같이 `INDIRECT_CALL_INET` 함수 매크로를 호출하게 된다. 둘의 차이점은 `dst_entry`라는 구조체를 바탕으로 처리되는 것들이다.
>`dst_entry`는 패킷을 처리하는데 네트워크 경로에 대한 정보를 저장하는 구조체이다. `skb` 구조체 안에 포인터로 가리키고 있으며, `input`과 `output` 함수 포인터를 가지고 있다. 각각 패킷이 입력될 때와 출력될 때 호출되는 함수들이다.

### 2.1 skb_dst()
```c
// include/linux/sk_buff.h
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
해당 sk_buff 구조체의 목적지를 반환한다. 목적지인 dst_entry 구조체의 주소는 `_skb_refdst`에 특정 비트(`SKB_DST_PTRMASK`)에 저장되어 있고, 나머지 비트(`SKB_DST_NOREF`)는 참조 횟수(refcount)가 있는지 없는지를 나타낸다. 

WARN_ON 함수 매크로를 실행한다. 다만 동일한 이름의 함수가 많아 정확하지 않다. refcount가 없을 때, 또는 RCU lock을 잡지 못할 때 fprintf로 stderr에 오류문구를 출력한다.
```c
// tools/include/asm/bug.h
#define __WARN_printf(arg...)	do { fprintf(stderr, arg); } while (0)

#define WARN(condition, format...) ({		\
	int __ret_warn_on = !!(condition);	\
	if (unlikely(__ret_warn_on))		\
		__WARN_printf(format);		\
	unlikely(__ret_warn_on);		\
})

#define WARN_ON(condition) ({					\
	int __ret_warn_on = !!(condition);			\
	if (unlikely(__ret_warn_on))				\
		__WARN_printf("assertion failed at %s:%d\n",	\
				__FILE__, __LINE__);		\
	unlikely(__ret_warn_on);				\
})
```

```c
// include/linux/sk_buff.h
/*
 * @dev: Device we arrived on/are leaving by
 * @_skb_refdst: destination entry (with norefcount bit)
 * @head: Head of buffer
 * @network_header: Network layer header
 */
 struct sk_buff {
	union {
		struct net_device	*dev;
		/* Some protocols might use this space to store information,
		 * while device pointer would be NULL.
		 * UDP receive path is one user.
		 */
		unsigned long		dev_scratch;
	};
 	union {
		struct {
			unsigned long	_skb_refdst;
			void		(*destructor)(struct sk_buff *skb);
		};
	__u16			network_header;
	unsigned char		*head;
};
```

### 2.2. INDIRECT_CALL_INET()
```c
// include/net/dst.h
struct dst_entry {
	struct net_device       *dev;
	struct  dst_ops	        *ops;
	unsigned long		_metrics;
	unsigned long           expires;
#ifdef CONFIG_XFRM
	struct xfrm_state	*xfrm;
#else
	void			*__pad1;
#endif
	int			(*input)(struct sk_buff *);
	int			(*output)(struct net *net, struct sock *sk, struct sk_buff *skb);
};
```

```c
// include/linux/indirect_call_wrapper.h
/*
 * INDIRECT_CALL_$NR - wrapper for indirect calls with $NR known builtin
 *  @f: function pointer
 *  @f$NR: builtin functions names, up to $NR of them
 *  @__VA_ARGS__: arguments for @f
 *
 * Avoid retpoline overhead for known builtin, checking @f vs each of them and
 * eventually invoking directly the builtin function. The functions are checked
 * in the given order. Fallback to the indirect call.
 */
#define INDIRECT_CALL_1(f, f1, ...)					\
	({								\
		likely(f == f1) ? f1(__VA_ARGS__) : f(__VA_ARGS__);	\
	})
#define INDIRECT_CALL_2(f, f2, f1, ...)					\
	({								\
		likely(f == f2) ? f2(__VA_ARGS__) :			\
				  INDIRECT_CALL_1(f, f1, __VA_ARGS__);	\
	})


/*
 * We can use INDIRECT_CALL_$NR for ipv6 related functions only if ipv6 is
 * builtin, this macro simplify dealing with indirect calls with only ipv4/ipv6
 * alternatives
 */
#if IS_BUILTIN(CONFIG_IPV6)
#define INDIRECT_CALL_INET(f, f2, f1, ...) \
	INDIRECT_CALL_2(f, f2, f1, __VA_ARGS__)
#elif IS_ENABLED(CONFIG_INET)
#define INDIRECT_CALL_INET(f, f2, f1, ...) INDIRECT_CALL_1(f, f1, __VA_ARGS__)
#else
#define INDIRECT_CALL_INET(f, f2, f1, ...) f(__VA_ARGS__)
#endif
```
IPv6이라면 (`CONFIG_IPV6`가 정의되어 있다면) f2 함수(`ip6_input()`)를 실행한다.
아니고 만약에 CONFIG_INET이  true라면 f1함수(`ip_local_deliver()`)를 실행한다.
둘 다 아니면 f 함수(`input`)를 실행한다.
CONFIG_INET은 `net/Kconfig` 파일 내에 있고, IPv4를 사용할 수 있으면 true로 저장하는 것으로 보인다.
```
config INET
	bool "TCP/IP networking"
	help
	  These are the protocols used on the Internet and on most local
	  Ethernets. It is highly recommended to say Y here (this will enlarge
	  your kernel by about 400 KB), since some programs (e.g. the X window
	  system) use TCP/IP even if your machine is not connected to any
	  other computer. You will get the so-called loopback device which
	  allows you to ping yourself (great fun, that!).

	  For an excellent introduction to Linux networking, please read the
	  Linux Networking HOWTO, available from
	  <http://www.tldp.org/docs.html#howto>.

	  If you say Y here and also to "/proc file system support" and
	  "Sysctl support" below, you can change various aspects of the
	  behavior of the TCP/IP code by writing to the (virtual) files in
	  /proc/sys/net/ipv4/*; the options are explained in the file
	  <file:Documentation/networking/ip-sysctl.rst>.

	  Short answer: say Y.
```

---
**결론**: sk_buff 구조체 타입의 매개변수 skb에는 사전에 만들어지는 dst_entry 구조체가 저장된 메모리 주소가 `skb_refdst` 변수의 특정 비트에 저장되어 있고, 이를 `skb_dst()`함수로 들고 오고, 이 dst_entry 구조체 내부에 input 함수 포인터가 있고 ip4인지 ip6인지에 따라 두 함수 `ip_local_deliver()` 또는 `ip6_input()`함수의 주소가 저장되어 있다. `INDIRECT_CALLABLE_DECLARE` 매크로 함수에서는 `input`에 저장된 함수를 실행한다.

---
## 3. ip_local_deliever
```c title=ip_local_deliver코드
// net/ipv4/ip_input.c
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

### 3.1. dev_net()
```c
// include/linux/netdevice.h
/*
 * @nd_net: Network namespace this network device is inside
 */
struct net_device {
	possible_net_t			nd_net;
};
/*
 * Net namespace inlines
 */
static inline
struct net *dev_net(const struct net_device *dev)
{
	return read_pnet(&dev->nd_net);
}
```

```c
// include/net/net_namespace.h
typedef struct {
#ifdef CONFIG_NET_NS
	struct net __rcu *net;
#endif
} possible_net_t;

static inline struct net *read_pnet(const possible_net_t *pnet)
{
#ifdef CONFIG_NET_NS
	return rcu_dereference_protected(pnet->net, true);
#else
	return &init_net;
#endif
}
```
skb(`sk_buff`)->dev(`net_device`)->nd_net(`possible_net_t`)->net(`net`)을 RCU 방식으로 읽어온다. 

### 3.2. ip_hdr(), ip_is_fragment()
```c
// include/net/ip.h
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}
```

```c
// include/linux/sk_buff.h
/*
 * @head: Head of buffer
 * @network_header: Network layer header
 */
 struct sk_buff {
	union {
	__u16			network_header;
	unsigned char		*head;
};
static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}
```
`head`: 패킷의 데이터가 시작되는 메모리 공간의 주소 시작점
`network_header`: head에서 몇 바이트 떨어진 곳부터 IP 헤더가 시작되는지를 나타내는 offset값
따라서 `skb->head + skb->network_header`로 iphdr 구조체가 시작되는 위치를 알 수 있음

---
### 3.3. ip_defrag()
```c
/* Process an incoming IP datagram fragment. */
int ip_defrag(struct net *net, struct sk_buff *skb, u32 user)
{
	struct net_device *dev = skb->dev ? : skb_dst(skb)->dev;
	int vif = l3mdev_master_ifindex_rcu(dev);
	struct ipq *qp;

	__IP_INC_STATS(net, IPSTATS_MIB_REASMREQDS);

	/* Lookup (or create) queue header */
	qp = ip_find(net, ip_hdr(skb), user, vif);
	if (qp) {
		int ret;

		spin_lock(&qp->q.lock);

		ret = ip_frag_queue(qp, skb);

		spin_unlock(&qp->q.lock);
		ipq_put(qp);
		return ret;
	}

	__IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
	kfree_skb(skb);
	return -ENOMEM;
}
```

dev에 skb->dev을 넣는다. 만약 없으면 skb의 목적지의 dev를 넣는다.
ip queue를 위한 포인터 qp를 선언한다.
queue pointer (qp)에 맞는 incomplete datagram queue를 찾아준다. (`ip_find()`)
만약 없다면 새로운 queue를 생성해준다. 

qp가 존재하는 경우, `ip_frag_queue()`를 실행한다. 
ip queue에 qp를 넣어준다. 

ip_find()
Find the correct entry in the "incomplete datagrams" queue for
this IP datagram, and create new one, if nothing is found.

>`ip_find()`함수를 통해 해당 flow에 맞는 queue header를 찾게 된다. 이 큐는 fragment를 해소하기 위한 큐로, frag가 된 패킷들을 하나로 모아 합쳐서 복구하는 역할을 하게 된다.

[[ip_find()]]
[[ip_frag_queue() incomplete]]
#### 3.3.1. l3mdev_master_ifindex_rcu()
```c
// net/l3mdev/l3mdev.c

// 
/**
 *	l3mdev_master_ifindex_rcu - get index of L3 master device
 *	@dev: targeted interface
 */

int l3mdev_master_ifindex_rcu(const struct net_device *dev)
{
	int ifindex = 0;

	if (!dev)
		return 0;

	if (netif_is_l3_master(dev)) {
		ifindex = dev->ifindex;
	} else if (netif_is_l3_slave(dev)) {
		struct net_device *master;
		struct net_device *_dev = (struct net_device *)dev;

		/* netdev_master_upper_dev_get_rcu calls
		 * list_first_or_null_rcu to walk the upper dev list.
		 * list_first_or_null_rcu does not handle a const arg. We aren't
		 * making changes, just want the master device from that list so
		 * typecast to remove the const
		 */
		master = netdev_master_upper_dev_get_rcu(_dev);
		if (master)
			ifindex = master->ifindex;
	}

	return ifindex;
}
EXPORT_SYMBOL_GPL(l3mdev_master_ifindex_rcu);
```
매개변수로 받은 `net_device`가 L3 마스터라면 해당 `net_device`의 인터페이스 인덱스 (`ifindex`)를 반환
L3 슬레이브라면 마스터를 찾고 마스터의 ifindex를 반환

**L3 마스터, 슬레이브**
L3계층(네트워크 레이어)에서 네트워크 인터페이스들은 논리적으로 트리 구조처럼 연결되어 있음
상위 인터페이스를 마스터, 하위 인터페이스를 슬레이브로 지칭함
```c
// include/linux/netdevice.h
static inline bool netif_is_l3_master(const struct net_device *dev)
{
	return dev->priv_flags & IFF_L3MDEV_MASTER;
}
static inline bool netif_is_l3_slave(const struct net_device *dev)
{
	return dev->priv_flags & IFF_L3MDEV_SLAVE;
}
```

```c
// net/core/dev.c
/**
 * netdev_master_upper_dev_get_rcu - Get master upper device
 * @dev: device
 *
 * Find a master upper device and return pointer to it or NULL in case
 * it's not there. The caller must hold the RCU read lock.
 */
struct net_device *netdev_master_upper_dev_get_rcu(struct net_device *dev)
{
	struct netdev_adjacent *upper;

	upper = list_first_or_null_rcu(&dev->adj_list.upper,
				       struct netdev_adjacent, list);
	if (upper && likely(upper->master))
		return upper->dev;
	return NULL;
}
EXPORT_SYMBOL(netdev_master_upper_dev_get_rcu);
```
### 3.3.2 ip_find()
```c
/* Describe an entry in the "incomplete datagrams" queue. */
struct ipq {
	struct inet_frag_queue q;

	u8		ecn; /* RFC3168 support */
	u16		max_df_size; /* largest frag with DF set seen */
	int             iif;
	unsigned int    rid;
	struct inet_peer *peer;
};

/* Find the correct entry in the "incomplete datagrams" queue for
 * this IP datagram, and create new one, if nothing is found.
 */
static struct ipq *ip_find(struct net *net, struct iphdr *iph,
			   u32 user, int vif)
{
	struct frag_v4_compare_key key = {
		.saddr = iph->saddr,
		.daddr = iph->daddr,
		.user = user,
		.vif = vif,
		.id = iph->id,
		.protocol = iph->protocol,
	};
	struct inet_frag_queue *q;

	q = inet_frag_find(net->ipv4.fqdir, &key);
	if (!q)
		return NULL;

	return container_of(q, struct ipq, q);
}
```

>`inet_frag_find()`함수를 통해 해당하는 `inet_frag_queue`타입의 구조체 변수를 가져오고, 이를 `container_of()`함수를 통해 이를 가지고 있는 `ipq` 구조체를 리턴하게 된다. 
>
>이 때 `inet_frag_find()`함수를 간단하게 설명하자면, `rhashtable_lookup()`함수를 호출하여 유효한 `inet_frag_queue`를 가져오게 된다. 이는 hash_table을 뒤지게 되고, 이 때 `net->ipv4`의 `fqdir`이라는 멤버변수를 가져온다. 이는 frag queue directory로, frag queue를 관리하는 구조체이다. 이 구조체 안에는 `rhashtable`이라는 멤버변수를 가지고 있는데, 이를 바탕으로 lookup이 진행되는 것이다.

ip_hdr 구조체 내부의 시작주소, 목적지 주소, vif, id, 프로토콜 등으로 해쉬키값을 만들어서 `inet_frag_queue` 구조체의 주소를 들고 온다. 이때 ipq 구조체는 멤버 변수로 이를 가지고 있으므로 `container_of()` 함수 매크로로 ipq 구조체의 주소를 들고 온다.

fqdir 구조체 내부에는 rhashtable 구조체를 멤버변수로 가지고 있어서 해쉬함수로 찾을 수 있는 것으로 보이지만 아직 내부 코드까지 살펴보지 않음.

```c
/* TODO : call from rcu_read_lock() and no longer use refcount_inc_not_zero() */
struct inet_frag_queue *inet_frag_find(struct fqdir *fqdir, void *key)
{
	/* This pairs with WRITE_ONCE() in fqdir_pre_exit(). */
	long high_thresh = READ_ONCE(fqdir->high_thresh);
	struct inet_frag_queue *fq = NULL, *prev;

	if (!high_thresh || frag_mem_limit(fqdir) > high_thresh)
		return NULL;

	rcu_read_lock();

	prev = rhashtable_lookup(&fqdir->rhashtable, key, fqdir->f->rhash_params);
	if (!prev)
		fq = inet_frag_create(fqdir, key, &prev);
	if (!IS_ERR_OR_NULL(prev)) {
		fq = prev;
		if (!refcount_inc_not_zero(&fq->refcnt))
			fq = NULL;
	}
	rcu_read_unlock();
	return fq;
}
EXPORT_SYMBOL(inet_frag_find);
```
RCU 락을 잡고 해쉬테이블을 참조하여 매개변수로 받은 key값에 대응하는 inet_frag_queue 구조체를 찾는다. 만약 없다면 새로 만들고 반환한다.
```c
/* Per netns frag queues directory */
struct fqdir {
	/* sysctls */
	long			high_thresh;
	long			low_thresh;
	int			timeout;
	int			max_dist;
	struct inet_frags	*f;
	struct net		*net;
	bool			dead;

	struct rhashtable       rhashtable ____cacheline_aligned_in_smp;

	/* Keep atomic mem on separate cachelines in structs that include it */
	atomic_long_t		mem ____cacheline_aligned_in_smp;
	struct work_struct	destroy_work;
	struct llist_node	free_list;
};

/**
 * struct inet_frag_queue - fragment queue
 *
 * @node: rhash node
 * @key: keys identifying this frag.
 * @timer: queue expiration timer
 * @lock: spinlock protecting this frag
 * @refcnt: reference count of the queue
 * @rb_fragments: received fragments rb-tree root
 * @fragments_tail: received fragments tail
 * @last_run_head: the head of the last "run". see ip_fragment.c
 * @stamp: timestamp of the last received fragment
 * @len: total length of the original datagram
 * @meat: length of received fragments so far
 * @mono_delivery_time: stamp has a mono delivery time (EDT)
 * @flags: fragment queue flags
 * @max_size: maximum received fragment size
 * @fqdir: pointer to struct fqdir
 * @rcu: rcu head for freeing deferall
 */
struct inet_frag_queue {
	struct rhash_head	node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list	timer;
	spinlock_t		lock;
	refcount_t		refcnt;
	struct rb_root		rb_fragments;
	struct sk_buff		*fragments_tail;
	struct sk_buff		*last_run_head;
	ktime_t			stamp;
	int			len;
	int			meat;
	u8			mono_delivery_time;
	__u8			flags;
	u16			max_size;
	struct fqdir		*fqdir;
	struct rcu_head		rcu;
};
```

### 3.3.3. ip_frag_queue()
```c
/* Add new segment to existing queue. */
static int ip_frag_queue(struct ipq *qp, struct sk_buff *skb)
{
	struct net *net = qp->q.fqdir->net;// 네트워크 네임스페이스
	int ihl, end, flags, offset;// 헤더 길이, 데이터 끝 위치, 플래그그
	struct sk_buff *prev_tail;//이전 마지막 fragment
	struct net_device *dev;//skb가 들어온 네트워크 디바이스
	unsigned int fragsize;// 새로 들어온 fragment 크기
	int err = -ENOENT;
	SKB_DR(reason);
	u8 ecn;

	/* If reassembly is already done, @skb must be a duplicate frag. */
	// 새로 들어온 fragment가 이미 합쳐졌다면 넘어감
	if (qp->q.flags & INET_FRAG_COMPLETE) {
		SKB_DR_SET(reason, DUP_FRAG);
		goto err;
	}

	// a. ipq 상태를 확인하고 초기화 시도, 안되면 제거 후 넘어감
	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}

	// b. offset, flag 계산
	ecn = ip4_frag_ecn(ip_hdr(skb)->tos);
	offset = ntohs(ip_hdr(skb)->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);

	// c. end 계산
	/* Determine the position of this fragment. */
	end = offset + skb->len - skb_network_offset(skb) - ihl;
	err = -EINVAL;

	// d. fragment 검증
	/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrupted.
		 */
		if (end < qp->q.len ||
		    ((qp->q.flags & INET_FRAG_LAST_IN) && end != qp->q.len))
			goto discard_qp;
		qp->q.flags |= INET_FRAG_LAST_IN;
		qp->q.len = end;
	} else {
		if (end&7) {
			end &= ~7;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
		if (end > qp->q.len) {
			/* Some bits beyond end -> corruption. */
			if (qp->q.flags & INET_FRAG_LAST_IN)
				goto discard_qp;
			qp->q.len = end;
		}
	}
	if (end == offset)
		goto discard_qp;

	err = -ENOMEM;
	if (!pskb_pull(skb, skb_network_offset(skb) + ihl))
		goto discard_qp;

	err = pskb_trim_rcsum(skb, end - offset);
	if (err)
		goto discard_qp;

	// e. fragment 삽입
	/* Note : skb->rbnode and skb->dev share the same location. */
	dev = skb->dev;
	/* Makes sure compiler wont do silly aliasing games */
	barrier();

	prev_tail = qp->q.fragments_tail;
	err = inet_frag_queue_insert(&qp->q, skb, offset, end);
	if (err)
		goto insert_error;

	if (dev)
		qp->iif = dev->ifindex;

	qp->q.stamp = skb->tstamp;
	qp->q.mono_delivery_time = skb->mono_delivery_time;
	qp->q.meat += skb->len;
	qp->ecn |= ecn;
	add_frag_mem_limit(qp->q.fqdir, skb->truesize);
	if (offset == 0)
		qp->q.flags |= INET_FRAG_FIRST_IN;

	// f. fragment 크기 계산, 최대 fragment 크기 계산
	fragsize = skb->len + ihl;

	if (fragsize > qp->q.max_size)
		qp->q.max_size = fragsize;

	if (ip_hdr(skb)->frag_off & htons(IP_DF) &&
	    fragsize > qp->max_df_size)
		qp->max_df_size = fragsize;

	if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
	    qp->q.meat == qp->q.len) {
		unsigned long orefdst = skb->_skb_refdst;

		skb->_skb_refdst = 0UL;
		err = ip_frag_reasm(qp, skb, prev_tail, dev);
		skb->_skb_refdst = orefdst;
		if (err)
			inet_frag_kill(&qp->q);
		return err;
	}

	// g. 재조립되지 않은 경우
	skb_dst_drop(skb);
	skb_orphan(skb);
	return -EINPROGRESS;

insert_error:
	if (err == IPFRAG_DUP) {
		SKB_DR_SET(reason, DUP_FRAG);
		err = -EINVAL;
		goto err;
	}
	err = -EINVAL;
	__IP_INC_STATS(net, IPSTATS_MIB_REASM_OVERLAPS);
discard_qp:
	inet_frag_kill(&qp->q);
	__IP_INC_STATS(net, IPSTATS_MIB_REASMFAILS);
err:
	kfree_skb_reason(skb, reason);
	return err;
}
```

**a. ipq 상태를 확인하고 초기화 시도, 안되면 제거 후 넘어감**
```c
// ipq 상태를 확인하고 초기화 시도, 안되면 제거 후 넘어감
	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}
```

```c
/* Is the fragment too far ahead to be part of ipq? */
static int ip_frag_too_far(struct ipq *qp)
{
	struct inet_peer *peer = qp->peer;
	unsigned int max = qp->q.fqdir->max_dist;
	unsigned int start, end;

	int rc;

	if (!peer || !max)
		return 0;

	start = qp->rid;
	end = atomic_inc_return(&peer->rid);
	qp->rid = end;

	rc = qp->q.fragments_tail && (end - start) > max;

	if (rc)
		__IP_INC_STATS(qp->q.fqdir->net, IPSTATS_MIB_REASMFAILS);

	return rc;
}

static int ip_frag_reinit(struct ipq *qp)
{
	unsigned int sum_truesize = 0;

	if (!mod_timer(&qp->q.timer, jiffies + qp->q.fqdir->timeout)) {
		refcount_inc(&qp->q.refcnt);
		return -ETIMEDOUT;
	}

	sum_truesize = inet_frag_rbtree_purge(&qp->q.rb_fragments,
					      SKB_DROP_REASON_FRAG_TOO_FAR);
	sub_frag_mem_limit(qp->q.fqdir, sum_truesize);

	qp->q.flags = 0;
	qp->q.len = 0;
	qp->q.meat = 0;
	qp->q.rb_fragments = RB_ROOT;
	qp->q.fragments_tail = NULL;
	qp->q.last_run_head = NULL;
	qp->iif = 0;
	qp->ecn = 0;

	return 0;
}

```

---
**b. offset 계산**
```c
	ecn = ip4_frag_ecn(ip_hdr(skb)->tos);
	offset = ntohs(ip_hdr(skb)->frag_off);
	// flags와 offset 분리
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);
```

```c
// include/net/ip.h
static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}
```
iphdr->ihl은 word 단위이므로 바이트 단위로 연산하기 위해 4를 곱함

---
**c. end 계산**
```c
	/* Determine the position of this fragment. */
	end = offset + skb->len - skb_network_offset(skb) - ihl;
	err = -EINVAL;
```

```c
static inline int skb_network_offset(const struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}
static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
	return skb->head + skb->network_header;
}
```

**결론** offset + skb->len - ((skb->head + skb->network_header) - skb->data ) - ihl
- offset: 해당 fragment의 데이터 부분이 원본 IP 패킷 내에서 시작하는 바이트 위치
- skb->len: 해당 sk_buff의 전체 길이
- skb_network_offset(skb): 현재 sk_buff에서 IP 헤더가 시작하는 위치
- ihl: IP 헤더의 길이
	--> end = offset + (fragment의 길이) = IP 데이터그램 내에서 fragment 데이터의 끝나는 바이트 위치

---

**d. 마지막 fragment인지 확인**
```c
/* Is this the final fragment? */
	if ((flags & IP_MF) == 0) {
		/* If we already have some bits beyond end
		 * or have different end, the segment is corrupted.
		 */
		if (end < qp->q.len ||
		    ((qp->q.flags & INET_FRAG_LAST_IN) && end != qp->q.len))
			goto discard_qp;
		qp->q.flags |= INET_FRAG_LAST_IN;
		qp->q.len = end;
	} 
```

```c
// include/net/ip.h
/* IP flags. */
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/
```
- 첫번째 if문: fragment가 마지막인지(`0`) 아닌지(`1`) 확인
	- 마지막이면 전체 데이터그램의 크기를 계산 가능함
	- 만약 이상한 fragment면(기존 길이보다 작거나 이미 마지막이 들어왔는데 최종 길이랑 다르면) 해당 패킷은 버림
	- ipq 구조체에 마지막 패킷이 들어왔다는 플래그(`INET_FRAG_LAST_IN` )설정
	- `(struct ipq *)qp->(struct inet_frag_queue)q.(int)len`에 `end`를 저장
```c
	else {
		if (end&7) {
			end &= ~7;
			if (skb->ip_summed != CHECKSUM_UNNECESSARY)
				skb->ip_summed = CHECKSUM_NONE;
		}
		if (end > qp->q.len) {
			/* Some bits beyond end -> corruption. */
			if (qp->q.flags & INET_FRAG_LAST_IN)
				goto discard_qp;
			qp->q.len = end;
		}
	}
	if (end == offset)
		goto discard_qp;
```
- 아직 마지막 fragment가 아니면
	- fragment는 8바이트 단위이기 때문에 항상 8의 배수임. 따라서 뒤 3비트에 값이 있으면 그걸 버림(`end &= ~7;`)
	```c
	/*
	 * @ip_summed: Driver fed us an IP checksum
	 */
struct sk_buff {
	__u8			ip_summed:2;
}
	```
	 - NIC에서 이미 체크섬을 계산했다면 값을 수정했으니 다시 계산해야하는 상태(`CHECKSUM_NONE`)로 바꿈
	 - 새로 들어온 fragment의 끝 위치가 지금까지의 전체 길이보다 크다면
		 - 이미 마지막 fragment를 받았다면 해당 패킷은 버림
		 - 아니면 전체 길이를 `end`로 저장
- 시작 위치와 끝 위치가 같다면 해당 패킷은 버림

---

**e. fragment 삽입**
```c
	/* Note : skb->rbnode and skb->dev share the same location. */
	dev = skb->dev;
	/* 컴파일러 메모리 최적화를 방지해 dev값 유지 */
	barrier();

	// iqp 구조체 내에서 가장 뒤 fragment의 sk_buff 들고 오기
	/**
	 * struct inet_frag_queue - fragment queue 
	 * @fragments_tail: received fragments tail
	 */
	prev_tail = qp->q.fragments_tail;
	err = inet_frag_queue_insert(&qp->q, skb, offset, end);
	if (err)
		goto insert_error;

	/* ipq 구조체에 새로 받은 sk_buff의 내용을 저장 */
	if (dev)
		qp->iif = dev->ifindex;

	qp->q.stamp = skb->tstamp;
	qp->q.mono_delivery_time = skb->mono_delivery_time;
	qp->q.meat += skb->len;
	qp->ecn |= ecn;
	add_frag_mem_limit(qp->q.fqdir, skb->truesize);
	
	// 패킷에서 처음 들어온 fragment면 처음 들어왔다는 플래그 표시
	if (offset == 0)
		qp->q.flags |= INET_FRAG_FIRST_IN;

```


```c
int inet_frag_queue_insert(struct inet_frag_queue *q, struct sk_buff *skb,
			   int offset, int end)
{
	struct sk_buff *last = q->fragments_tail;

	/* RFC5722, Section 4, amended by Errata ID : 3089
	 *                          When reassembling an IPv6 datagram, if
	 *   one or more its constituent fragments is determined to be an
	 *   overlapping fragment, the entire datagram (and any constituent
	 *   fragments) MUST be silently discarded.
	 *
	 * Duplicates, however, should be ignored (i.e. skb dropped, but the
	 * queue/fragments kept for later reassembly).
	 */
	if (!last)
		fragrun_create(q, skb);  /* First fragment. */
	else if (FRAG_CB(last)->ip_defrag_offset + last->len < end) {
		/* This is the common case: skb goes to the end. */
		/* Detect and discard overlaps. */
		if (offset < FRAG_CB(last)->ip_defrag_offset + last->len)
			return IPFRAG_OVERLAP;
		if (offset == FRAG_CB(last)->ip_defrag_offset + last->len)
			fragrun_append_to_last(q, skb);
		else
			fragrun_create(q, skb);
	} else {
		/* Binary search. Note that skb can become the first fragment,
		 * but not the last (covered above).
		 */
		struct rb_node **rbn, *parent;

		rbn = &q->rb_fragments.rb_node;
		do {
			struct sk_buff *curr;
			int curr_run_end;

			parent = *rbn;
			curr = rb_to_skb(parent);
			curr_run_end = FRAG_CB(curr)->ip_defrag_offset +
					FRAG_CB(curr)->frag_run_len;
			if (end <= FRAG_CB(curr)->ip_defrag_offset)
				rbn = &parent->rb_left;
			else if (offset >= curr_run_end)
				rbn = &parent->rb_right;
			else if (offset >= FRAG_CB(curr)->ip_defrag_offset &&
				 end <= curr_run_end)
				return IPFRAG_DUP;
			else
				return IPFRAG_OVERLAP;
		} while (*rbn);
		/* Here we have parent properly set, and rbn pointing to
		 * one of its NULL left/right children. Insert skb.
		 */
		fragcb_clear(skb);
		rb_link_node(&skb->rbnode, parent, rbn);
		rb_insert_color(&skb->rbnode, &q->rb_fragments);
	}

	FRAG_CB(skb)->ip_defrag_offset = offset;

	return IPFRAG_OK;
}
EXPORT_SYMBOL(inet_frag_queue_insert);
```

Red-Black 트리 구조로 fragment들을 관리함
- inet_frag_queue 구조체가 비어있으면 노드 새로 생성(`fragrun_create()`)
- skbuff 구조체에서 ipfrag_skb_cb 구조체 포인터를 들고 와서 새로운 fragment의 끝 위치가 마지막 fragment의 끝 위치보다 더 뒤에 있을 때
```c
/* Use skb->cb to track consecutive/adjacent fragments coming at
 * the end of the queue. Nodes in the rb-tree queue will
 * contain "runs" of one or more adjacent fragments.
 *
 * Invariants:
 * - next_frag is NULL at the tail of a "run";
 * - the head of a "run" has the sum of all fragment lengths in frag_run_len.
 */
struct ipfrag_skb_cb {
	union {
		struct inet_skb_parm	h4;
		struct inet6_skb_parm	h6;
	};
	struct sk_buff		*next_frag;
	int			frag_run_len;
	int			ip_defrag_offset;
};
#define FRAG_CB(skb)		((struct ipfrag_skb_cb *)((skb)->cb))
```

- 
	- 새로운 fragment의 시작 위치가 마지막 fragment 끝 위치보다 앞에 있으면 겹침(`IPFRAG_OVERLAP`)
	- 시작 위치가 끝이랑 바로 이어지면 그대로 붙임(`fragrun_append_to_last(q, skb)`)
	- 새로운 fragment의 시작 위치가 마지막 fragment의 끝 위치보다 뒤에 떨어져 있다면 새 run을 만듦
- 새로운 fragment의 끝 위치가 마지막 fragment의 끝 위치보다 더 앞에 있다면(중간에 삽입되어야 한다면)
	- 이진 탐색으로 rbtree에서 삽입 위치를 탐색
	- 중복 시 `IPFRAG_DUP`반환
	- 위치가 겹친다면 `IPFRAG_OVERLAP`반환
- 정상적이라면 삽입(
- ```c
		/* Here we have parent properly set, and rbn pointing to
		 * one of its NULL left/right children. Insert skb.
		 */
		fragcb_clear(skb); // skb->cd 구조체의 멤버들 초기화
		rb_link_node(&skb->rbnode, parent, rbn); // rbtree 연결
		rb_insert_color(&skb->rbnode, &q->rb_fragments); // 색깔 계산
  ```
---
**f. fragment 크기 계산 및 갱신, 최대 fragment 크기 계산**
```c
	fragsize = skb->len + ihl;

	if (fragsize > qp->q.max_size)
		qp->q.max_size = fragsize;

	if (ip_hdr(skb)->frag_off & htons(IP_DF) &&
	    fragsize > qp->max_df_size)
		qp->max_df_size = fragsize;
```
- fragsize: 새로운 fragment의 전체 길이
- 만약 전체 길이가 fragment 큐의 원소 중 최대 길이보다 크다면 최대 길이를 수정한다
- IP 헤더가 더 이상 fragment를 만들지 못하게 설정되어있고, 새로운 fragment의 전체 길이가 기존의 fragment를 만들지 못하는 최대 길이보다 크다면 수정한다.
---
**e. fragment 결합 검사 후 결합 시도**
```c
if (qp->q.flags == (INET_FRAG_FIRST_IN | INET_FRAG_LAST_IN) &&
    qp->q.meat == qp->q.len) {
	unsigned long orefdst = skb->_skb_refdst;

	skb->_skb_refdst = 0UL;
	err = ip_frag_reasm(qp, skb, prev_tail, dev);
	skb->_skb_refdst = orefdst;
	if (err)
		inet_frag_kill(&qp->q);
	return err;
}
```
- 첫번째와 마지막 fragment가 도작했고, 수신받은 fragment 데이터 길이(`qp->q.meat`)가 전체 데이터 길이(`qp->q.len`)와 일치한다면
	- 모든 fragment들을 합침(`ip_frag_reasm()`) 합치는 도중에는 `_skb_refdsk` 변수를 `(unsigned long)0`으로 바꿈
	- 오류 발생 시 해당 fragment 큐를 삭제
---
**g. 재조립되지 않은 경우**
```c
	skb_dst_drop(skb);
	skb_orphan(skb);
	return -EINPROGRESS;
```

```c
// include/net/dst.h
/**
 * skb_dst_drop - drops skb dst
 * @skb: buffer
 *
 * Drops dst reference count if a reference was taken.
 */
 // skb가 참조하는 목적지(dst_entry) 참조를 해체
static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->_skb_refdst) {
		refdst_drop(skb->_skb_refdst);
		skb->_skb_refdst = 0UL;
	}
}

// 목적지 참조 카운트를 사용한다면 참조 카운트를 감소
static inline void refdst_drop(unsigned long refdst)
{
	if (!(refdst & SKB_DST_NOREF))
		dst_release((struct dst_entry *)(refdst & SKB_DST_PTRMASK));
}

// dst_entry.__rcuref.refcnt를 감소시킴(rcuref_put())
// 카운트가 0이라면 메모리를 해제하는 함수(dst_destroy_rcu())를 실행
void dst_release(struct dst_entry *dst)
{
	if (dst && rcuref_put(&dst->__rcuref))
		call_rcu_hurry(&dst->rcu_head, dst_destroy_rcu);
}
EXPORT_SYMBOL(dst_release);
```


```c
// include/linux/skbuff.h
/*
 * @sk: Socket we are owned by
 * @destructor: Destruct function
 */
 struct sk_buff {
	struct sock		*sk;
	void		(*destructor)(struct sk_buff *skb);
;}

/**
 *	skb_orphan - orphan a buffer
 *	@skb: buffer to orphan
 *
 *	If a buffer currently has an owner then we call the owner's
 *	destructor function and make the @skb unowned. The buffer continues
 *	to exist but is no longer charged to its former owner.
 */
static inline void skb_orphan(struct sk_buff *skb)
{
	if (skb->destructor) {
		skb->destructor(skb);
		skb->destructor = NULL;
		skb->sk		= NULL;
	} else {
		BUG_ON(skb->sk);
	}
}
```