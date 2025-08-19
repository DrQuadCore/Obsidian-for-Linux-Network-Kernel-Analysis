
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

**왜 이중 구조로 확인할까?** 
결론적으로 dst_input() 함수는 INDIRECT_CALLABLE_DECLARE 함수 매크로를 통해서 ipv4인지 ipv6인지에 따라 함수를 선택하고, 둘 다 아닌 경우에는 dst_entry의 멤버변수 input 함수 포인터에 저장된 함수를 실행함. 일반적인 경우 input 내에도 ipv4, ipv6인지에 따라 두 함수 ip6_input, ip_local_deliver 중 하나의 주소가 저장되었겠지만 추후 다른 함수를 저장하여 dst_input()의 결과로 실행되는 함수를 쉽게 바꿀 수 있게 하기 위함으로 보임

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
	int ihl, end, flags, offset;// 헤더 길이, 데이터 끝 위치, 플래그
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

	// ipq 상태를 확인하고 초기화 시도, 안되면 제거 후 넘어감
	if (!(IPCB(skb)->flags & IPSKB_FRAG_COMPLETE) &&
	    unlikely(ip_frag_too_far(qp)) &&
	    unlikely(err = ip_frag_reinit(qp))) {
		ipq_kill(qp);
		goto err;
	}

	ecn = ip4_frag_ecn(ip_hdr(skb)->tos);
	offset = ntohs(ip_hdr(skb)->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;		/* offset is in 8-byte chunks */
	ihl = ip_hdrlen(skb);

	/* Determine the position of this fragment. */
	end = offset + skb->len - skb_network_offset(skb) - ihl;
	err = -EINVAL;

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