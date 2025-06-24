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
